from sqlalchemy.orm import Session
import logging
from app.infrastructure.database import models
from app.infrastructure.external.scraper import scrape_google_play
from app.infrastructure.external.gemini_client import GeminiClient
from app.infrastructure.security import check_security_alerts
from app.infrastructure.prompt_manager import build_analysis_prompt


logger = logging.getLogger(__name__)

async def run_analysis_flow(db: Session, analysis_id: int):
    analysis = db.query(models.AppAnalysis).filter(models.AppAnalysis.id == analysis_id).first()
    if not analysis: return
    try:
        # 1. POBIERANIE DANYCH (Scraper)
        store_info = scrape_google_play(analysis.package_name)
        sec_report = check_security_alerts(db, analysis.package_name, analysis.vendor_name, [analysis.signing_cert_hash])

        analysis.is_up_to_date = not store_info.get("is_outdated", False) # Negacja, bo baza ma "up_to_date", a scraper "outdated"
        analysis.privacy_policy_exists = bool(store_info.get("privacy_policy_url"))

        if not store_info.get("exists_in_store", False):
            analysis.is_up_to_date = False




        # 3. PRZYGOTOWANIE DANYCH DLA PROMPT_MANAGERA
        # Łączymy surowe dane z urządzenia z naszymi interpretacjami (flagi)
        device_data = {
                "app_name": analysis.app_name,
                "package_name": analysis.package_name,
                "version_code": analysis.version_code,
                "is_debuggable": analysis.is_debuggable,
                "is_fingerprinting_suspected": analysis.is_fingerprinting_suspected, # Ważne dla AI
                "is_from_store": analysis.is_from_store,
                "target_sdk": analysis.target_sdk,
                "signature_status": sec_report['status'], # TRUSTED, DANGER, etc.
                "permissions": analysis.permissions,
                "libraries": analysis.libraries
            }

        # 4. GENEROWANIE PROMPTU
        # Wstrzyknie device_data do {device_json}
        prompt = build_analysis_prompt(device_data, store_info)

        gemini = GeminiClient()
        ai_result = await gemini.generate_analysis(prompt)

        # ZAPIS WYNIKÓW
        analysis.status = "COMPLETED"
        analysis.security_light = ai_result.get("security_score", 0)
        analysis.privacy_light = ai_result.get("privacy_score", 0)
        analysis.short_summary = ai_result.get("short_summary")
        
        analysis.full_report = {
            **ai_result,
            "store_info_snapshot": store_info,
            "security_alerts": sec_report['alerts']
        }
        
    except Exception as e:
        logger.error(f"AI Analysis FAILED for {analysis.package_name}: {e}")
        analysis.status = "FAILED"
        raise e
    finally:
        db.commit()