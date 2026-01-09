# app/scraper.py
from google_play_scraper import app, exceptions
import logging

logger = logging.getLogger(__name__)

def scrape_google_play(package_name: str, user_version_name: str = None) -> dict:
    """
    Pobiera dane o aplikacji ze sklepu Google Play (Polska).
    """
    logger.info(f"🔍 Scraping Google Play: {package_name}")
    
    try:
        # Pobieranie danych
        store_data = app(
            package_name,
            lang='pl', 
            country='pl'
        )
        
        latest_version = store_data.get('version', 'Nieznana')
        is_outdated = False
        
        if user_version_name and latest_version != 'Nieznana':
            if user_version_name != latest_version:
                is_outdated = True

        return {
            "exists_in_store": True,
            "title": store_data.get('title'),
            "developer": store_data.get('developer'),
            "score": store_data.get('score'),
            "store_version": latest_version,
            "is_outdated": is_outdated,
            "privacy_policy": store_data.get('privacyPolicy'),
            "updated_timestamp": store_data.get('updated'),
            
            "summary": store_data.get('summary'),       # Krótkie hasło reklamowe
            "description": store_data.get('description') # Pełny opis funkcji
        }

    except exceptions.NotFoundError:
        logger.warning(f"⚠️ App {package_name} not found in Store.")
        return {
            "exists_in_store": False,
            "error": "NOT_FOUND"
        }
    except Exception as e:
        logger.error(f"❌ Scraper error for {package_name}: {e}")
        return {
            "exists_in_store": False,
            "error": str(e)
        }