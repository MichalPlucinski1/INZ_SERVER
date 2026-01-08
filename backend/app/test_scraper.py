# test_scraper.py
from google_play_scraper import app, exceptions
import json
import datetime

# Funkcja pomocnicza do wyświetlania dat w JSON
def default_converter(o):
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()

def check_app_in_store(package_name, user_version_name=None):
    print(f"\n🔍 Sprawdzam w Google Play: {package_name}...")
    
    try:
        # 1. Pobieranie danych ze sklepu
        # lang='pl', country='pl' zapewnia opisy po polsku
        store_data = app(
            package_name,
            lang='pl', 
            country='pl' 
        )
        
        # 2. Wyciąganie kluczowych informacji
        latest_version = store_data.get('version', 'Nieznana')
        updated_timestamp = store_data.get('updated', 0)
        
        # Konwersja timestampa na czytelną datę
        last_update_date = datetime.datetime.fromtimestamp(updated_timestamp) if updated_timestamp else "Nieznana"

        # 3. Logika porównawcza (Symulacja)
        is_outdated = False
        if user_version_name and latest_version != 'Nieznana':
            # Bardzo proste porównanie stringów (w produkcji można użyć biblioteki packaging.version)
            if user_version_name != latest_version:
                is_outdated = True

        # 4. Przygotowanie raportu
        report = {
            "exists_in_store": True,
            "title": store_data.get('title'),
            "developer": store_data.get('developer'),
            "score": store_data.get('score'),
            "installs": store_data.get('installs'),
            "store_version": latest_version,
            "user_version": user_version_name,
            "is_outdated": is_outdated,
            "last_update": last_update_date,
            "privacy_policy_url": store_data.get('privacyPolicy'),
            "description_short": store_data.get('summary')
        }
        
        print("✅ ZNALEZIONO! Oto co widzi AI:")
        print(json.dumps(report, indent=4, default=default_converter, ensure_ascii=False))
        return report

    except exceptions.NotFoundError:
        print("⚠️ Aplikacja NIE ISTNIEJE w sklepie Google Play (lub została usunięta).")
        return {"exists_in_store": False}
    except Exception as e:
        print(f"❌ Inny błąd scrapera: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    # Test 1: Signal (Aplikacja istniejąca, podajemy starszą wersję żeby wymusić flagę is_outdated)
    check_app_in_store("org.thoughtcrime.securesms", user_version_name="5.0.0")

    # Test 2: Latarka (Aplikacja z Twojego przykładu - prawdopodobnie nie istnieje lub inna nazwa)
    check_app_in_store("com.suspicious.flashlight", user_version_name="1.0")
    
    # Test 3: WhatsApp (Test na żywym organizmie bez wersji usera)
    check_app_in_store("com.whatsapp")