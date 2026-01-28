# app/scraper.py
from google_play_scraper import app, exceptions
import logging
import requests

logger = logging.getLogger(__name__)

def check_url_reachability(url: str) -> dict:
    """
    Sprawdza, czy podany URL działa (zwraca kod 200-299).
    Zwraca słownik ze statusem i kodem HTTP.
    """
    if not url:
        return {"alive": False, "status_code": 0, "error": "EMPTY_URL"}
    
    # Proste filtry na "fake" linki tekstowe
    if "example.com" in url or url.strip() == "":
        return {"alive": False, "status_code": 0, "error": "FAKE_DOMAIN"}

    try:
        # Najpierw próbujemy HEAD (szybciej, nie pobiera treści)
        response = requests.head(url, timeout=3, allow_redirects=True)
        
        # Niektóre serwery blokują HEAD, więc jeśli błąd > 400, próbujemy GET
        if response.status_code >= 400:
            response = requests.get(url, timeout=3, stream=True)
            
        is_alive = 200 <= response.status_code < 400
        return {
            "alive": is_alive, 
            "status_code": response.status_code, 
            "final_url": response.url
        }
        
    except requests.exceptions.Timeout:
        return {"alive": False, "status_code": 408, "error": "TIMEOUT"}
    except requests.exceptions.ConnectionError:
        return {"alive": False, "status_code": 503, "error": "CONNECTION_ERROR"}
    except Exception as e:
        return {"alive": False, "status_code": 0, "error": str(e)}

def scrape_google_play(package_name: str, user_version_name: str = None) -> dict:
    """
    Pobiera dane o aplikacji ze sklepu Google Play (Polska).
    Jeśli brakuje opisów w PL, próbuje pobrać dane z wersji angielskiej (US).
    """
    logger.info(f"🔍 Scraping Google Play: {package_name}")
    
    try:
        # 1. Pobieranie danych ze sklepu PL
        try:
            store_data = app(
                package_name,
                lang='pl', 
                country='pl'
            )
        except exceptions.NotFoundError:
            # Jeśli nie ma w PL, spróbujmy od razu US (niektóre apki są tylko na rynek US)
            logger.info(f" Nie znaleziono {package_name} w PL, próba US...")
            store_data = app(
                package_name,
                lang='en', 
                country='us'
            )

        # 1b. Fallback na język angielski (uzupełnianie braków)
        # Sprawdzamy czy opis lub summary są puste/bardzo krótkie
        description = store_data.get('description', '')
        summary = store_data.get('summary', '')

        if not description or not summary or len(description) < 10:
            logger.info(f"📝 Ubogie dane w PL dla {package_name}. Pobieranie wersji EN...")
            try:
                store_data_en = app(
                    package_name,
                    lang='en', 
                    country='us'
                )
                # Uzupełniamy tylko puste pola, zachowując polski tytuł itp.
                if not description:
                    store_data['description'] = store_data_en.get('description')
                if not summary:
                    store_data['summary'] = store_data_en.get('summary')
                
                # Czasami release notes są tylko po angielsku
                if not store_data.get('recentChanges'):
                    store_data['recentChanges'] = store_data_en.get('recentChanges')

            except Exception as e_en:
                logger.warning(f" Nie udało się pobrać wersji EN (fallback): {e_en}")

        # 2. Logika wersji
        latest_version = store_data.get('version', 'Nieznana')
        is_outdated = False
        if user_version_name and latest_version != 'Nieznana':
            # Proste porównanie stringów (warto rozważyć bibliotekę 'packaging' w przyszłości)
            if user_version_name != latest_version:
                is_outdated = True
        
        # 3. Weryfikacja Polityki Prywatności
        privacy_url = store_data.get('privacyPolicy')
        privacy_check = check_url_reachability(privacy_url)

        return {
            "exists_in_store": True,
            "title": store_data.get('title'),
            "developer": store_data.get('developer'),
            "score": store_data.get('score'),
            "store_version": latest_version,
            "is_outdated": is_outdated,
            "updated_timestamp": store_data.get('updated'),
            "summary": store_data.get('summary'),
            "description": store_data.get('description'),
            "recent_changes": store_data.get('recentChanges'), # Dodatkowo zwracamy listę zmian
            
            # Sekcja Polityki
            "privacy_policy_url": privacy_url,
            "privacy_policy_check": privacy_check
        }

    except exceptions.NotFoundError:
        logger.warning(f" App {package_name} not found in Store (PL & US).")
        return {
            "exists_in_store": False,
            "error": "NOT_FOUND"
        }
    except Exception as e:
        logger.error(f" Scraper error for {package_name}: {e}")
        return {
            "exists_in_store": False,
            "error": str(e)
        }