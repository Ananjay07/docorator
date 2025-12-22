# backend/app/prompts.py
# Store all prompt templates here for reuse

RESUME_PROMPT = r"""
You are an AI document generator.
Generate ONLY valid JSON (no explanation, no markdown, no extra text).
Fill the JSON exactly using these keys and types.

CRITICAL INSTRUCTION: 
1. Use the provided User Input values where available.
2. **AUTO-GENERATION:** If 'bullets' (for experience) or 'description' (for projects) are EMPTY list [], you MUST generate high-quality, professional bullet points or descriptions.
   - Base the generated content on the 'title'/'name' and the 'User Intent/Context' provided below.
   - For Experience: Generate 3-4 result-oriented bullet points (Use keywords related to the job title).
   - For Projects: Generate a concise technical description including the tech stack.
   - For Achievements: If empty, generate impressive achievements based on the 'User Intent/Context' (e.g., if user mentions 'Hackathon winner', add it).
   - DO NOT leave these empty if the user provided context or a title.

User Input: {user_input}
User Intent/Context (Style/Emphasis): {ai_context}

Return this exact JSON structure:
{{
  "name": "",
  "contact": "",
  "email": "",
  "phone": "",
  "location": "",
  "summary": "",
  "skills": [],
  "experience_list": [
    {{
      "title": "",
      "company": "",
      "period": "",
      "location": "",
      "bullets": []
    }}
  ],
  "projects": [
    {{
      "name": "",
      "tech_stack": "",
      "description": "",
      "impact": ""
    }}
  ],
  "education": [
    {{
      "degree": "",
      "institute": "",
      "year": "",
      "grade": ""
    }}
  ],
  "achievements": []
}}
"""

SOP_PROMPT = r"""
You are an AI document generator.
Generate ONLY valid JSON (no explanation, no markdown).
Fill the JSON for a Statement of Purpose (SOP).
CRITICAL INSTRUCTION: Use the provided User Input values where available. For any MISSING values, GENERATE CREATIVE, PERSUASIVE CONTENT suitable for an SOP.
User Input: {user_input}
User Intent/Context (Style/Focus): {ai_context}

Return this exact JSON structure:
{{
  "applicant_name": "",
  "email": "",
  "phone": "",
  "location": "",
  "intro": "",
  "academic_background": "",
  "research_experience": "",
  "why_program": "",
  "career_goals": "",
  "conclusion": ""
}}
"""

LETTER_PROMPT = r"""
You are an AI document generator.
Generate ONLY valid JSON.
Fill the JSON for a Formal Letter.
CRITICAL INSTRUCTION: Use the provided User Input values where available. For any MISSING values, GENERATE REALISTIC CONTENT for a formal letter.
User Input: {user_input}
User Intent/Context (Tone/Formality): {ai_context}

Return this exact JSON structure:
{{
  "sender_name": "",
  "sender_address": "",
  "receiver_name": "",
  "receiver_address": "",
  "receiver_salutation": "",
  "date": "Today's date",
  "subject": "",
  "body": "Body of the letter"
}}
"""

CONTRACT_PROMPT = r"""
You are an AI document generator.
Generate ONLY valid JSON.
Fill the JSON for a Contract.
CRITICAL INSTRUCTION: Use the provided User Input values where available. For any MISSING inputs, GENERATE REALISTIC CONTRACT TERMS.
User Input: {user_input}
User Intent/Context (Specific Terms): {ai_context}

Return this exact JSON structure:
{{
  "party_a": "",
  "party_b": "",
  "date_a": "",
  "date_b": "",
  "scope": "",
  "responsibilities": "",
  "payment_terms": "",
  "confidentiality_clause": "",
  "termination_clause": ""
}}
"""

REPORT_PROMPT = r"""
You are an AI document generator.
Generate ONLY valid JSON.
Fill the JSON for a Report.
CRITICAL INSTRUCTION: Use the provided User Input values where available. For any MISSING inputs, GENERATE REALISTIC REPORT CONTENT.
User Input: {user_input}
User Intent/Context (Focus/Objectives): {ai_context}

Return this exact JSON structure:
{{
  "title": "",
  "author": "",
  "date": "",
  "executive_summary": "",
  "objectives": "",
  "methodology": "",
  "findings": "",
  "recommendations": "",
  "conclusion": ""
}}
"""

PROMPTS = {
    "resume": RESUME_PROMPT,
    "sop": SOP_PROMPT,
    "letter": LETTER_PROMPT,
    "contract": CONTRACT_PROMPT,
    "report": REPORT_PROMPT
}

# RAW_TO_JSON_PROMPT was removed as we switched to structured-only guided mode.


