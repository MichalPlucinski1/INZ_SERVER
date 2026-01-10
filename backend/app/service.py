# app/service.py
import os
import json
import logging
import datetime
from pathlib import Path
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List, Dict
from sqlalchemy import tuple_
from . import models, schemas
from .database import SessionLocal
from .scraper import scrape_google_play 
from .prompt_manager import build_analysis_prompt
from .security import check_security_alerts

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

# --- KONFIGURACJA LOGOWANIA PLIKOWEGO ---
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True) # Upewniamy się, że folder istnieje
AI_LOG_FILE = LOG_DIR / "ai_traffic.log"

def log_ai_interaction(package_name: str, prompt: str, response_text: str):
    """
    Zapisuje parę Prompt-Response do pliku tekstowego dla celów audytowych/debugowania.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    separator = "=" * 50
    
    try:
        with open(AI_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n{separator}\n")
            f.write(f"TIME: {timestamp}\n")
            f.write(f"APP: {package_name}\n")
            f.write(f"{separator}\n")
            f.write(f"--- PROMPT ---\n{prompt}\n")
            f.write(f"\n--- AI RESPONSE ---\n{response_text}\n")
            f.write(f"{separator}\n")
    except Exception as e:
        logger.error(f"Failed to write AI log: {e}")

# --- MODEL AI ---
class AiFlatResponse(BaseModel):
    security_score: int
    privacy_score: int
    short_summary: str
    verdict_details: str
    risk_factors: List[str]
    positive_factors: List[str]

# --- LOGIKA BIZNESOWA ---

def get_or_create_analysis(db: Session, app_payload: schemas.AppPayload, background_tasks):

    primary_hash = ""
    if app_payload.signing_cert_hashes:
        primary_hash = app_payload.signing_cert_hashes[0].replace(":", "").replace(" ", "").upper()
    else:
        primary_hash = "UNKNOWN"

    existing_analysis = db.query(models.AppAnalysis).filter(
        models.AppAnalysis.package_name == app_payload.package_name,
        models.AppAnalysis.version_code == app_payload.version_code,
        models.AppAnalysis.signing_cert_hash == primary_hash
    ).first()

    if existing_analysis:
        # Retry logic: Jeśli FAILED lub (COMPLETED ale ocena 0) -> ponów
        if existing_analysis.status == "FAILED" or (existing_analysis.status == "COMPLETED" and existing_analysis.security_light == 0):
            logger.info(f"🔄 RETRY: {app_payload.package_name}")
            existing_analysis.status = "PENDING"
            db.commit()
            background_tasks.add_task(run_ai_analysis_worker, existing_analysis.id, app_payload.model_dump())
        return existing_analysis

    # Nowy rekord
    logger.info(f"🆕 NEW: {app_payload.package_name}")
    new_analysis = models.AppAnalysis(
        package_name=app_payload.package_name,
        version_code=app_payload.version_code,
        signing_cert_hash=primary_hash,
        app_name=app_payload.app_name,
        vendor_name=app_payload.vendor,
        
        # Flagi techniczne
        is_from_store=app_payload.is_from_store,
        installer_package=app_payload.installer_package,
        is_debuggable=app_payload.is_debuggable,
        has_exported_components=app_payload.has_exported_components,
        is_fingerprinting_suspected=app_payload.is_fingerprinting_suspected,
        target_sdk=app_payload.target_sdk,
        
        permissions=app_payload.permissions,
        libraries=app_payload.libraries,
        status="PENDING"
    )
    db.add(new_analysis)
    db.commit()
    db.refresh(new_analysis)

    background_tasks.add_task(run_ai_analysis_worker, new_analysis.id, app_payload.model_dump())
    return new_analysis

async def run_ai_analysis_worker(analysis_id: int, payload_dict: dict):
    db = SessionLocal()
    try:
        analysis = db.query(models.AppAnalysis).filter(models.AppAnalysis.id == analysis_id).first()
        if not analysis: return

        # 1. SCRAPER
        store_info = scrape_google_play(
            package_name=payload_dict.get('package_name'),
            user_version_name=payload_dict.get('version_name')
        )
        
        # Aktualizacja na podstawie scrapera
        if store_info.get('exists_in_store'):
            analysis.is_up_to_date = not store_info.get('is_outdated', False)
            analysis.privacy_policy_exists = bool(store_info.get('privacy_policy'))
        else:
            analysis.is_up_to_date = False 
            analysis.privacy_policy_exists = False

        # 2. SECURITY CHECK
        security_report = check_security_alerts(
            db, 
            package_name=payload_dict.get('package_name'),
            claimed_vendor=payload_dict.get('vendor'),
            incoming_hashes=payload_dict.get('signing_cert_hashes', [])
        )
        
        # Mapowanie statusu
        sec_status = security_report['status']
        if sec_status == "TRUSTED":
            analysis.cert_status = "trusted"
        elif sec_status in ["DANGER", "WARNING", "MISMATCH"]:
            analysis.cert_status = "suspicious"
        else:
            analysis.cert_status = "no_info"

        # Wstrzykiwanie wyników weryfikacji do danych dla promptu
        store_info['security_alerts'] = "\n".join(security_report['alerts'])
        store_info['signature_status'] = sec_status

        # 3. AI PROMPT & GENERATION
        prompt = build_analysis_prompt(payload_dict, store_info)
        
        response = client.models.generate_content(
            model='gemini-2.0-flash', 
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type='application/json',
                response_schema=AiFlatResponse
            )
        )
        
        # --- LOGOWANIE INTERAKCJI ---
        log_ai_interaction(payload_dict.get('package_name'), prompt, response.text)
        # ----------------------------

        ai_data = json.loads(response.text)
        
        # 4. ZAPIS WYNIKÓW
        analysis.status = "COMPLETED"
        analysis.security_light = ai_data.get("security_score", 0)
        analysis.privacy_light = ai_data.get("privacy_score", 0)
        analysis.short_summary = ai_data.get("short_summary", "")
        
        analysis.full_report = {
            "verdict": ai_data.get("verdict_details"),
            "risk_factors": ai_data.get("risk_factors", []),
            "positive_factors": ai_data.get("positive_factors", []),
            "store_info": store_info,
            "security_check": security_report
        }

        db.commit()
        logger.info(f"✅ Finished: {analysis.package_name}")

    except Exception as e:
        logger.error(f"❌ Error: {str(e)}")
        # Spróbujmy zalogować błąd do pliku, jeśli to błąd AI
        try:
            log_ai_interaction(payload_dict.get('package_name'), "ERROR_DURING_PROCESSING", str(e))
        except: pass

        try:
            analysis.status = "FAILED"
            analysis.short_summary = f"Error: {str(e)}"
            db.commit()
        except: pass
    finally:
        db.close()





def get_or_create_batch_analysis(db: Session, apps_payload: List[schemas.AppPayload], background_tasks) -> Dict[str, models.AppAnalysis]:
    """
    Optymalizuje obsługę wielu aplikacji naraz (Batching).
    Zamiast 57 zapytań do bazy, robi 1 SELECT i 1 INSERT.
    """
    results_map = {}
    new_records = []
    tasks_to_schedule = []

    # 1. Przygotowanie kluczy do wyszukiwania (package_name, version_code, hash)
    # Tworzymy mapę {unique_key: payload}
    payload_map = {}
    search_keys = []

    for app in apps_payload:
        primary_hash = "UNKNOWN"
        if app.signing_cert_hashes:
            # Hash już jest wyczyszczony w main.py, ale dla pewności:
            primary_hash = app.signing_cert_hashes[0].replace(":", "").replace(" ", "").upper()
        
        # Klucz unikalności analizy: Pakiet + Wersja + Hash
        key = (app.package_name, app.version_code, primary_hash)
        payload_map[key] = app
        search_keys.append(key)

    # 2. BATCH SELECT: Pobieramy istniejące analizy jednym zapytaniem
    # Używamy konstrukcji SQL: WHERE (col1, col2, col3) IN ((v1,v2,v3), ...)
    if search_keys:
        existing_analyses = db.query(models.AppAnalysis).filter(
            tuple_(models.AppAnalysis.package_name, models.AppAnalysis.version_code, models.AppAnalysis.signing_cert_hash)\
            .in_(search_keys)
        ).all()
    else:
        existing_analyses = []

    # 3. Mapowanie istniejących wyników
    for analysis in existing_analyses:
        # Retry logic: Jeśli FAILED lub (COMPLETED ale ocena 0) -> oznaczamy do ponowienia
        if analysis.status == "FAILED" or (analysis.status == "COMPLETED" and analysis.security_light == 0):
            logger.info(f"🔄 BATCH RETRY: {analysis.package_name}")
            analysis.status = "PENDING"
            # Znajdź payload dla tej analizy
            key = (analysis.package_name, analysis.version_code, analysis.signing_cert_hash)
            if key in payload_map:
                tasks_to_schedule.append((analysis.id, payload_map[key].model_dump()))
        
        results_map[analysis.package_name] = analysis

    # 4. Wykrywanie brakujących (NEW)
    # Sprawdzamy, których kluczy z payload_map nie znaleźliśmy w bazie
    for key, app_payload in payload_map.items():
        if app_payload.package_name not in results_map:
            # Tworzymy nowy rekord PENDING
            new_analysis = models.AppAnalysis(
                package_name=app_payload.package_name,
                version_code=app_payload.version_code,
                signing_cert_hash=key[2], # Hash z klucza
                app_name=app_payload.app_name,
                vendor_name=app_payload.vendor,
                
                # Flagi techniczne
                is_from_store=app_payload.is_from_store,
                installer_package=app_payload.installer_package,
                is_debuggable=app_payload.is_debuggable,
                has_exported_components=app_payload.has_exported_components,
                is_fingerprinting_suspected=app_payload.is_fingerprinting_suspected,
                target_sdk=app_payload.target_sdk,
                
                permissions=app_payload.permissions,
                libraries=app_payload.libraries,
                status="PENDING"
            )
            new_records.append(new_analysis)
            # Dodamy do tasks_to_schedule PO zapisie do bazy (żeby mieć ID)

    # 5. BULK INSERT: Zapisujemy wszystkie nowe rekordy jedną transakcją
    if new_records:
        logger.info(f"🆕 BATCH INSERT: Dodawanie {len(new_records)} nowych aplikacji.")
        db.add_all(new_records)
        db.commit() # Tylko jeden commit na 57 apek!
        
        # Odświeżamy ID i kolejkujemy zadania
        for analysis in new_records:
            db.refresh(analysis)
            results_map[analysis.package_name] = analysis
            
            # Znajdź payload
            key = (analysis.package_name, analysis.version_code, analysis.signing_cert_hash)
            if key in payload_map:
                tasks_to_schedule.append((analysis.id, payload_map[key].model_dump()))

    # 6. Kolejkowanie zadań w tle (FastAPI BackgroundTasks)
    for analysis_id, payload_dump in tasks_to_schedule:
        background_tasks.add_task(run_ai_analysis_worker, analysis_id, payload_dump)

    return results_map