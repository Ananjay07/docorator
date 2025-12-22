from docxtpl import DocxTemplate
from pathlib import Path
import logging

logger = logging.getLogger("docgen.template_renderer")

def render_docx(template_path: str, context: dict, out_path: str):
    """
    Renders a docx Jinja template with the provided context and saves it.
    `template_path` - path to a docx with docxtpl placeholders (Jinja)
    `context` - dict of placeholders -> values
    `out_path` - file path to write the rendered docx
    """
    tpl = DocxTemplate(template_path)
    tpl.render(context or {})
    tpl.save(out_path)
    logger.info("Saved rendered DOCX to %s", out_path)