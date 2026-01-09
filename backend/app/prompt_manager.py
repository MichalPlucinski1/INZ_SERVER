import os
import json
from pathlib import Path

# Ścieżka do katalogu z promptami (względem tego pliku)
PROMPTS_DIR = Path(__file__).parent / "prompts"

def build_analysis_prompt(device_data: dict, store_data: dict) -> str:
    """
    Ładuje szablon promptu i wstrzykuje do niego dane w formacie JSON.
    """
    try:
        prompt_path = PROMPTS_DIR / "analysis_v1.txt"
        
        with open(prompt_path, "r", encoding="utf-8") as f:
            template = f.read()
            
        # Konwersja słowników na ładny tekst JSON (dla czytelności modelu)
        device_json_str = json.dumps(device_data, indent=2, ensure_ascii=False)
        store_json_str = json.dumps(store_data, indent=2, ensure_ascii=False)
        
        # Wstrzyknięcie danych w placeholdery
        final_prompt = template.format(
            store_json=store_json_str,
            device_json=device_json_str
        )
        
        return final_prompt
        
    except FileNotFoundError:
        # Fallback w razie problemów z plikiem
        return f"CRITICAL ERROR: Prompt file not found. Analyze data: {device_data}"