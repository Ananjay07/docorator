from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Ensure data directory exists for persistence
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Azure Web App for Containers maps /home to persistent storage if configured.
# We prefer STORAGE_DIR env var, else default to local 'data' folder.
STORAGE_DIR = os.getenv("STORAGE_DIR", os.path.join(os.path.dirname(BASE_DIR), "data"))
os.makedirs(STORAGE_DIR, exist_ok=True)

DATA_DIR = STORAGE_DIR

SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.join(DATA_DIR, 'app.db')}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
