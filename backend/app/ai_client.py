import os
import json
import time
import google.generativeai as genai
from .prompts import PROMPTS

GEMINI_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_KEY:
    masked_key = GEMINI_KEY[:5] + "..." + GEMINI_KEY[-4:] if len(GEMINI_KEY) > 10 else "***"
    print(f"DEBUG: Loaded Gemini API Key: {masked_key}")
    genai.configure(api_key=GEMINI_KEY)

class GeminiError(Exception):
    pass

def call_gemini(prompt: str) -> dict:
    """Send prompt to Gemini model and return parsed JSON."""
    if not GEMINI_KEY:
         raise GeminiError("GEMINI_API_KEY not found in environment variables")

    model = genai.GenerativeModel('gemini-2.5-flash')
    retries = 3
    delay = 10
    text = ""

    for attempt in range(retries):
        try:
            response = model.generate_content(prompt)
            text = response.text
            break # Success, exit retry loop
        except Exception as e:
            if "429" in str(e) and attempt < retries - 1:
                print(f"Rate limit hit. Retrying in {delay}s... (Attempt {attempt+1}/{retries})")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                raise GeminiError(f"Gemini API error: {str(e)}")

    # Find JSON inside text
    try:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start == -1 or end == 0:
             raise ValueError("No JSON found in response")
        
        json_str = text[start:end]
        
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            # Handle "Extra data" error which happens if there's multiple JSONs or trailing junk
            if e.msg.startswith("Extra data"):
                # Use the position of the error to slice the string
                # e.pos is where the extra data starts
                return json.loads(json_str[:e.pos])
            else:
                raise e

    except Exception as e:
        raise GeminiError(f"JSON extraction error: {str(e)}\nGemini output: {text}")


def generate_structured_with_gemini(doc_type: str, user_fields: dict | None, ai_context: str | None):
    """
    Unified Generation Logic:
    Takes structured user inputs (rough drafts/points) AND user intent (ai_context)
    and uses the appropriate Prompt Template to generate the final polished JSON content.
    """

    if doc_type not in PROMPTS:
        raise GeminiError(f"No prompt found for document type: {doc_type}")

    base_prompt = PROMPTS[doc_type]

    # Insert user_fields or {} if none. 
    # The prompt itself is instructed to use these values and expand on them.
    prompt = base_prompt.format(
        user_input=json.dumps(user_fields or {}),
        ai_context=ai_context or "Generate a standard professional document."
    )

    return call_gemini(prompt)