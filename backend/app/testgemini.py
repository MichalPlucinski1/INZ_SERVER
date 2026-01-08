# test_gemini.py
import os
import sys

print("--- DIAGNOSTYKA GEMINI ---")

# 1. Sprawdzamy czy biblioteka jest widoczna
try:
    from google import genai
    from google.genai import types
    print("✅ Biblioteka 'google-genai' jest zainstalowana.")
except ImportError:
    print("❌ BŁĄD KRYTYCZNY: Nie znaleziono biblioteki 'google-genai'!")
    print("Upewnij się, że w requirements.txt jest: google-genai>=0.3.0")
    print("I że przebudowałeś obraz (docker-compose up --build).")
    sys.exit(1)

# 2. Sprawdzamy klucz API
# (Jeśli uruchomisz to w Dockerze, pobierze klucz z .env kontenera)
api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    # Fallback dla testów lokalnych (jeśli odpalasz bez dockera)
    # Odkomentuj i wpisz klucz ręcznie TYLKO DO TESTÓW jeśli .env nie działa
    # api_key = "AIzaSy.....TwojKlucz"
    pass

if not api_key:
    print("❌ BŁĄD: Zmienna GOOGLE_API_KEY jest pusta.")
    sys.exit(1)
else:
    print(f"🔑 Klucz API wykryty: {api_key[:5]}...******")

# 3. Próba połączenia
try:
    print("📡 Próba połączenia z modelem 'gemini-1.5-flash'...")
    
    client = genai.Client(api_key=api_key)
    
    prompt = "Jesteś prostym testem. Odpowiedz tylko JSONem: {'status': 'ok', 'message': 'Hello World'}"
    
    response = client.models.generate_content(
        model='gemini-1.5-flash',
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type='application/json'
        )
    )
    
    print("\n✅ SUKCES! Otrzymano odpowiedź:")
    print(response.text)

except Exception as e:
    print(f"\n❌ BŁĄD POŁĄCZENIA: {e}")
    # Częsty błąd: quota exceeded, bad request, geo-block