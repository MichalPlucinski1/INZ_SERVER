# list_models.py
import os
from google import genai

print("--- LISTA MODELI (WERSJA PROSTA) ---")

api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    print("❌ Brak klucza API!")
    exit(1)

client = genai.Client(api_key=api_key)

try:
    print(f"📡 Pobieranie listy dla klucza: {api_key[:5]}...")
    
    # Pobieramy listę i wypisujemy po prostu nazwy
    for model in client.models.list():
        # W nowym SDK nazwa modelu jest w atrybucie .name lub .display_name
        # Ale sam obiekt model wydrukowany jako string pokaże nam wszystko
        print(f"🔹 ID: {model.name}")
        # print(f"   Info: {model}") # Odkomentuj jeśli chcesz widzieć pełne bebechy

except Exception as e:
    print(f"❌ BŁĄD: {e}")
    print("\nJeśli widzisz błąd 404 lub pusta listę, a jesteś w Polsce:")
    print("Google często wymaga podpięcia karty w Google Cloud Console (Billing),")
    print("nawet dla darmowego tieru, aby odblokować modele w regionie EU.")