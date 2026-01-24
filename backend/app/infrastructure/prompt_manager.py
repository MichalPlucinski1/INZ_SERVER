import os
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Ścieżka do katalogu z promptami
PROMPTS_DIR = Path(__file__).parent.parent / "prompts"

def build_analysis_prompt(device_data: dict, store_data: dict) -> str:
    """
    Ładuje szablon promptu i wstrzykuje do niego dane w formacie JSON.
    Używa .replace() zamiast .format(), aby uniknąć błędów przy klamrach JSON w treści promptu.
    """
    try:
        prompt_path = PROMPTS_DIR / "analysis_v3.txt"
        
        with open(prompt_path, "r", encoding="utf-8") as f:
            template = f.read()
            
        # Konwersja słowników na tekst JSON
        device_json_str = json.dumps(device_data, indent=2, ensure_ascii=False)
        store_json_str = json.dumps(store_data, indent=2, ensure_ascii=False)
        
        # ZMIANA: Używamy replace, bo .format() wywaliłby się na klamrach {} w przykładach JSON wewnątrz pliku txt
        final_prompt = template.replace("{store_json}", store_json_str)
        final_prompt = final_prompt.replace("{device_json}", device_json_str)
        
        return final_prompt
        
    except FileNotFoundError:
        logger.error(f"❌ Prompt file not found at {prompt_path}")
        return f"CRITICAL ERROR: Prompt file missing. Data: {device_data}"
    except Exception as e:
        logger.error(f"❌ Error building prompt: {str(e)}")
        raise e