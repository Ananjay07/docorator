from fastapi import FastAPI, HTTPException, Depends, Depends
from pydantic import BaseModel
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
import uuid
import logging
from typing import Optional, Dict
from dotenv import load_dotenv

load_dotenv(override=False)

from .template_renderer import render_docx
from .ai_client import generate_structured_with_gemini, GeminiError
from .database import engine, get_db, Base
from .models import User, Document
from .auth import get_password_hash, verify_password, create_access_token, get_current_user
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
import shutil

# Init Database Tables
Base.metadata.create_all(bind=engine)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("docgen")

BASE_DIR = Path(__file__).resolve().parent         # backend/app

# Use same persistent storage logic as database
import os
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", BASE_DIR.parent / "data"))
GENERATED = STORAGE_DIR / "generated"           # backend/generated or /home/data/generated
TEMPLATES_DIR = BASE_DIR / "templates"              # backend/app/templates

STOP_DIR_CREATION = GENERATED.mkdir(parents=True, exist_ok=True)
GENERATED.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)


from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Docorator Backend")

# Serve Static Assets (CSS, JS)
app.mount("/static", StaticFiles(directory="../frontend"), name="static")

# @app.get("/")
# async def read_index():
#     return FileResponse("../frontend/index.html")

@app.get("/")
def health_check():
    return {"status": "ok"}

# --- AUTH ROUTER ---

class UserSchema(BaseModel):
    email: str
    password: str
    full_name: str
    profession: str
    security_question: str
    security_answer: str

@app.post("/auth/signup")
def signup(user: UserSchema, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = User(
        email=user.email,
        hashed_password=get_password_hash(user.password),
        full_name=user.full_name,
        profession=user.profession,
        security_question=user.security_question,
        security_answer_hash=get_password_hash(user.security_answer) # Hash answer like password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "User created successfully"}

class UserProfile(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    profession: Optional[str] = None
    security_question: Optional[str] = None

    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    profession: Optional[str] = None

@app.get("/auth/me", response_model=UserProfile)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/auth/me", response_model=UserProfile)
def update_user_me(user_update: UserUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Update fields if provided
    if user_update.full_name is not None:
        current_user.full_name = user_update.full_name
    if user_update.profession is not None:
        current_user.profession = user_update.profession
    
    db.commit()
    db.refresh(current_user)
    return current_user

class GetQuestionRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    email: str
    security_answer: str
    new_password: str

@app.post("/auth/get-question")
def get_security_question(req: GetQuestionRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.security_question:
         raise HTTPException(status_code=400, detail="User has no security question set")
    return {"question": user.security_question}

@app.post("/auth/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
         raise HTTPException(status_code=404, detail="User not found")
    
    if not user.security_answer_hash:
          raise HTTPException(status_code=400, detail="User has no security answer set")
          
    if not verify_password(req.security_answer, user.security_answer_hash):
         raise HTTPException(status_code=400, detail="Incorrect security answer")
         
    # Reset Password
    user.hashed_password = get_password_hash(req.new_password)
    db.commit()
    return {"msg": "Password reset successfully"}

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=timedelta(days=7)
    )
    return {"access_token": access_token, "token_type": "bearer"}


# --- DASHBOARD ROUTER ---

# --- STARTUP DB MIGRATION CHECK ---
@app.on_event("startup")
def check_db_schema():
    # Simple migration for SQLite to add 'input_data' column if missing
    import sqlite3
    try:
        # Check if column exists
        with engine.connect() as conn:
            # This is specific to SQLite:
            # We can use raw sql or inspection.
            pass
            
        # Let's do a raw connection to be simple and safe against session mechanics
        # app.db path:
        db_path = STORAGE_DIR / "app.db"
        if not db_path.exists(): return
        
        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        # Get columns
        cur.execute("PRAGMA table_info(documents)")
        columns = [info[1] for info in cur.fetchall()]
        if "input_data" not in columns:
            logger.info("Migrating DB: Adding input_data column...")
            cur.execute("ALTER TABLE documents ADD COLUMN input_data JSON")
            con.commit()
            
        # Check users table for security columns
        cur.execute("PRAGMA table_info(users)")
        user_columns = [info[1] for info in cur.fetchall()]
        if "security_question" not in user_columns:
            logger.info("Migrating DB: Adding security columns to users...")
            cur.execute("ALTER TABLE users ADD COLUMN security_question TEXT")
            cur.execute("ALTER TABLE users ADD COLUMN security_answer_hash TEXT")
            con.commit()
            
        con.close()
            
    except Exception as e:
        logger.error(f"Migration check failed: {e}")

# --- DASHBOARD ROUTER ---

@app.get("/dashboard/documents")
def get_user_documents(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Return reverse sorted by ID (newest first)
    return db.query(Document).filter(Document.user_id == current_user.id).order_by(Document.id.desc()).all()

@app.get("/dashboard/doc/{doc_id}")
def get_document_details(doc_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id, Document.user_id == current_user.id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc

@app.delete("/dashboard/delete/{doc_id}")
def delete_document(doc_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id, Document.user_id == current_user.id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Try to delete physical files
    # We use similar logic to download search to find them
    # But strictly, we can just look for names we know.
    stored_path = BASE_DIR / doc.file_path
    stem = stored_path.stem
    parent_dir = stored_path.parent
    
    paths_to_check = [
        # Check explicit path
        stored_path,
        # Check stem variations in generated folder
        GENERATED / f"{stem}.docx",
        GENERATED / f"{stem}.pdf",
        GENERATED / f"{doc.doc_type}_{stem}.docx",
        GENERATED / f"{doc.doc_type}_{stem}.pdf",
    ]
    if "_" in stem:
        uid = stem.split("_")[-1]
        paths_to_check.append(GENERATED / f"{uid}.pdf")
        
    for p in paths_to_check:
        try:
             if p.exists():
                 os.remove(p)
                 logger.info(f"Deleted file: {p}")
        except Exception as e:
            logger.error(f"Failed to delete {p}: {e}")
            
    db.delete(doc)
    db.commit()
    return {"msg": "Document deleted"}


@app.get("/dashboard/download/{doc_id}")
def download_dashboard_doc(doc_id: int, format: str = "pdf", current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id, Document.user_id == current_user.id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Robust File Finding Strategy
    # stored 'doc.file_path' might be relative to BASE_DIR (backend/app), but files are scattered.
    # We will search in known directories.
    
    search_dirs = [
        GENERATED,                          # backend/data/generated (Current Standard)
        BASE_DIR.parent / "generated",      # backend/generated (Legacy)
        BASE_DIR / Path(doc.file_path).parent if doc.file_path else None # Fix: path is string, need Path()
    ]
    # Filter valid dirs
    search_dirs = [d for d in search_dirs if d and d.exists()]
    
    # Candidate filenames
    candidates = []
    
    # 1. Exact match for requested format by filename stems
    base_name = Path(doc.filename).stem
    
    if format == "docx":
        candidates.append(f"{base_name}.docx")
        # Legacy: {doc_type}_{uid}.docx if stem is just uid?
        candidates.append(f"{doc.doc_type}_{base_name}.docx")
        
    elif format == "pdf":
        candidates.append(f"{base_name}.pdf")
        # Legacy: uid.pdf if stem is doc_type_uid? 
        if "_" in base_name:
             uid = base_name.split("_")[-1]
             candidates.append(f"{uid}.pdf")

    target_file = None
    
    for folder in search_dirs:
        for fname in candidates:
            p = folder / fname
            if p.exists():
                target_file = p
                break
        if target_file: break

    if not target_file:
         # Last resort: Try resolving doc.file_path directly vs BASE_DIR
         p = BASE_DIR / doc.file_path
         if p.exists() and p.suffix == f".{format}":
             target_file = p
         
    if not target_file or not target_file.exists():
         raise HTTPException(status_code=404, detail=f"File ({format}) not found on server")
         
    return FileResponse(
            path=str(target_file),
            filename=target_file.name,
            media_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document' if format=='docx' else 'application/pdf'
        )

# --- GENERATION ---



class GenerateRequest(BaseModel):
    doc_type: str
    fields: Optional[Dict] = None
    use_gemini: bool = False
    ai_context: Optional[str] = None
    return_docx: bool = False


@app.post("/generate")
def generate(req: GenerateRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc_type = (req.doc_type or "").strip().lower()
    if not doc_type:
        raise HTTPException(status_code=400, detail="doc_type is required")

    template_path = TEMPLATES_DIR / f"{doc_type}_template.docx"
    if not template_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Template for '{doc_type}' not found at {template_path}"
        )

    # Get fields from client or Gemini
# Get fields from client or Gemini
    if req.use_gemini:
        try:
            fields = generate_structured_with_gemini(
                doc_type,
                req.fields or {},
                req.ai_context
            )

            if not isinstance(fields, dict):
                raise ValueError("AI returned non-dict fields")

            # Merge user-provided fields (like Name, Email) into AI fields
            # User fields take precedence if they are explicitly provided (non-empty)
            if req.fields:
                # User fields take precedence if they are explicitly provided (non-empty)
                # BUT: Do not overwrite generated lists (experience, etc.) with the user's "stub" lists.
                skip_keys = {"experience_list", "projects", "education", "achievements", "skills"}
                for k, v in req.fields.items():
                    if v and k not in skip_keys:
                        fields[k] = v

        except GeminiError as ge:
            logger.exception("Gemini generation failed")
            raise HTTPException(status_code=502, detail=f"AI generation failed: {str(ge)}")
        except Exception as e:
            logger.exception("Unexpected AI error")
            raise HTTPException(status_code=500, detail=f"AI generation failed: {str(e)}")

    else:
        # Manual mode
        if not req.fields:
            raise HTTPException(
                status_code=400,
                detail="fields is required when use_gemini is false"
            )
        fields = req.fields


    # Render DOCX
    unique_id = uuid.uuid4().hex[:8]
    fname = f"{doc_type}_{unique_id}.docx"
    out_docx = GENERATED / fname
    try:
        render_docx(str(template_path), fields or {}, str(out_docx))
        logger.info("Rendered DOCX: %s", out_docx)
    except Exception as e:
        logger.exception("Template rendering failed")
        raise HTTPException(status_code=500, detail=f"Template rendering failed: {str(e)}")

    # If caller wants the DOCX only, return it
    final_file = out_docx
    media_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

    if req.return_docx:
        if not out_docx.exists():
            raise HTTPException(status_code=500, detail="DOCX was not created")
        # Final file is already out_docx
    else:
        # Cross-platform PDF conversion
        # Updated Naming: use consistent nomenclature for PDF too: {doc_type}_{unique_id}.pdf
        pdf_name = f"{doc_type}_{unique_id}.pdf"
        pdf_output = GENERATED / pdf_name
        
        # import subprocess (already imported if not moved) - good practice to safeguard
        import subprocess
        import platform # ensure platform available
        
        if os.name == 'nt':  # Windows
            from docx2pdf import convert
            convert(str(out_docx), str(pdf_output))
        else:  # Linux (Azure)
            subprocess.run([
                "soffice", "--headless", "--convert-to", "pdf", "--outdir", 
                str(GENERATED), str(out_docx)
            ], check=True)
            
            # Libreoffice usually outputs same-name-as-input.pdf?
            # if out_docx is "resume_123.docx", it makes "resume_123.pdf"
            # Since our out_docx IS named consistent, we are good!
            # BUT: wait, we manually set pdf_output above. If libreoffice auto-names it, we just need to verify matches.
            pass # fallback checks below
            
        if pdf_output.exists():
            final_file = pdf_output
            media_type = 'application/pdf'
            
    # --- SAVE TO DATABASE ---
    # Store path relative to BASE_DIR (backend/app) that points to backend/data/generated
    # BASE_DIR/../data/generated/file == backend/data/generated/file
    rel_path = f"../data/generated/{final_file.name}"
    
    new_doc = Document(
        user_id=current_user.id,
        filename=final_file.name,
        file_path=rel_path,
        doc_type=doc_type,
        input_data=fields # Store inputs for editing
    )
    db.add(new_doc)
    db.commit()
    db.refresh(new_doc)


    return FileResponse(
        path=str(final_file),
        filename=final_file.name,
        media_type=media_type
    )
    # NOTE: Code flow continues to PDF generation if return_docx is False.
    # If return_docx is True, we return above.
    # We must insert DB saving logic BEFORE returning.

    # RE-WRITING LOGIC BLOCK TO FIX RETURNING EARLY


    # Generate PDF via LibreOffice (headless) - Azure/Linux compatible
    pdf_output = out_docx.with_suffix(".pdf")
    if not req.return_docx:
        try:
            import subprocess
            import platform

            if platform.system() == "Windows":
                # Keep docx2pdf for local Windows testing (if preferred) or use LibreOffice if installed
                from docx2pdf import convert
                convert(str(out_docx), str(pdf_output))
            else:
                # Linux/Container (Azure)
                cmd = [
                    "soffice",
                    "--headless",
                    "--convert-to", "pdf",
                    "--outdir", str(GENERATED),
                    str(out_docx)
                ]
                subprocess.run(cmd, check=True)
                
            logger.info("Generated PDF: %s", pdf_output)

        except Exception as e:
            logger.exception("PDF conversion failed")
            return JSONResponse(status_code=500, content={
                "error": "PDF conversion failed (Ensure LibreOffice is installed in container)", 
                "detail": str(e)
            })

        if not pdf_output.exists():
            logger.error("PDF output file missing after conversion")
            return JSONResponse(status_code=500, content={"error": "PDF generation produced no file"})

    return FileResponse(
        path=str(pdf_output),
        filename=pdf_output.name,
        media_type="application/pdf"
    )

    # Note: The original code returned FileResponse above, which STOPS execution.
    # We need to save to DB *BEFORE* returning the file response, or handle it differently.
    # But FileResponse is a streaming response.
    
    # Better approach: Save to DB first, then return.
    
    # Let's determine final output file (DOCX or PDF)
    final_file = pdf_output
    if req.return_docx:
        final_file = out_docx
        
    # Save to DB
    # We store path relative to BASE_DIR for portability, or use the filename if in known dir
    # generated folder is BASE_DIR.parent / "generated"
    # Let's store relative path from app/ folder? No, lets store relative from backend root.
    # BASE_DIR is .../backend/app
    # GENERATED is .../backend/generated
    
    rel_path = f"../generated/{final_file.name}"
    
    new_doc = Document(
        user_id=current_user.id,
        filename=final_file.name,
        file_path=rel_path,
        doc_type=doc_type
    )
    db.add(new_doc)
    db.commit()

    return FileResponse(
        path=str(final_file),
        filename=final_file.name,
        media_type='application/pdf' if final_file.suffix == '.pdf' else 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    )
# Reload trigger updated