# app/service.py
import asyncio
import random
import json
import logging
import os
import re
import datetime
from pathlib import Path
from typing import List, Dict, Any
from pydantic import BaseModel
from google import genai
from google.genai import types

from .database import SessionLocal
from .scraper import scrape_google_play 
from .prompt_manager import build_analysis_prompt
from .security import check_security_alerts
from . import models, schemas



gemini_lock = asyncio.Lock()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Inicjalizacja klienta Google AI (z prostym sprawdzeniem klucza)
api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    logger.error("❌ BRAK GOOGLE_API_KEY! Analiza AI nie zadziała.")
client = genai.Client(api_key=api_key)

# --- LOGOWANIE DO PLIKU (Nowa Funkcja) ---
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
AI_LOG_FILE = LOG_DIR / "ai_traffic.log"

def log_ai_traffic(package_name: str, msg_type: str, content: str):
    """
    Dopisuje zdarzenie do pliku logu.
    msg_type: "REQUEST" lub "RESPONSE"
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"\n[{timestamp}] [{package_name}] ====== {msg_type} ======\n"
    footer = "\n" + "="*50 + "\n"
    
    try:
        with open(AI_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(header)
            f.write(str(content))
            f.write(footer)
    except Exception as e:
        logger.error(f"Failed to write to AI log: {e}")

# --- MODEL AI ---
class PermissionsAnalysisData(BaseModel):
    dangerous_count: int
    summary: str

class AiFlatResponse(BaseModel):
    security_score: int       # 1-3
    privacy_score: int        # 1-3
    short_summary: str
    verdict_details: str
    risk_factors: List[str]
    positive_factors: List[str]
    permissions_analysis: PermissionsAnalysisData

# --- LOGIKA BIZNESOWA ---

def get_or_create_batch_analysis(db: SessionLocal, apps_payload: List[schemas.AppPayload], background_tasks):
    # (Ta funkcja pozostaje bez zmian, jak w Twoim poprzednim kodzie)
    # Skrót dla czytelności - wklej tu swoją funkcję get_or_create_batch_analysis
    # ...
    # Poniżej wklejam tylko niezbędne wywołanie workera:
    # background_tasks.add_task(run_ai_analysis_worker, analysis_id, payload_dump)
    
    # --- REIMPLEMENTACJA get_or_create_batch_analysis (Skrócona do kontekstu) ---
    from sqlalchemy import tuple_
    results_map = {}
    new_records = []
    tasks_to_schedule = []
    payload_map = {}
    search_keys = []

    for app in apps_payload:
        primary_hash = "UNKNOWN"
        if app.signing_cert_hashes:
            primary_hash = app.signing_cert_hashes[0].replace(":", "").replace(" ", "").upper()
        key = (app.package_name, app.version_code, primary_hash)
        payload_map[key] = app
        search_keys.append(key)

    if search_keys:
        existing_analyses = db.query(models.AppAnalysis).filter(
            tuple_(models.AppAnalysis.package_name, models.AppAnalysis.version_code, models.AppAnalysis.signing_cert_hash)\
            .in_(search_keys)
        ).all()
    else:
        existing_analyses = []

    for analysis in existing_analyses:
        if analysis.status == "FAILED" or (analysis.status == "COMPLETED" and analysis.security_light == 0):
            analysis.status = "PENDING"
            key = (analysis.package_name, analysis.version_code, analysis.signing_cert_hash)
            if key in payload_map:
                tasks_to_schedule.append((analysis.id, payload_map[key].model_dump()))
        results_map[analysis.package_name] = analysis

    for key, app_payload in payload_map.items():
        if app_payload.package_name not in results_map:
            new_analysis = models.AppAnalysis(
                package_name=app_payload.package_name,
                version_code=app_payload.version_code,
                signing_cert_hash=key[2],
                app_name=app_payload.app_name,
                vendor_name=app_payload.vendor,
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

    if new_records:
        db.add_all(new_records)
        db.commit()
        for analysis in new_records:
            db.refresh(analysis)
            results_map[analysis.package_name] = analysis
            key = (analysis.package_name, analysis.version_code, analysis.signing_cert_hash)
            if key in payload_map:
                tasks_to_schedule.append((analysis.id, payload_map[key].model_dump()))

    for analysis_id, payload_dump in tasks_to_schedule:
        background_tasks.add_task(run_ai_analysis_worker, analysis_id, payload_dump)

    return results_map


async def run_ai_analysis_worker(analysis_id: int, payload_dict: dict):
    db = SessionLocal()
    package_name = payload_dict.get('package_name', 'unknown')
    
    try:
        analysis = db.query(models.AppAnalysis).filter(models.AppAnalysis.id == analysis_id).first()
        if not analysis: return

        # 1. SCRAPER
        store_info = scrape_google_play(
            package_name=package_name,
            user_version_name=payload_dict.get('version_name')
        )
        
        if store_info.get('exists_in_store'):
            analysis.is_up_to_date = not store_info.get('is_outdated', False)
            analysis.privacy_policy_exists = bool(store_info.get('privacy_policy'))
        else:
            analysis.is_up_to_date = False 
            analysis.privacy_policy_exists = False

        # 2. SECURITY CHECK
        security_report = check_security_alerts(
            db, 
            package_name=package_name,
            claimed_vendor=payload_dict.get('vendor'),
            incoming_hashes=payload_dict.get('signing_cert_hashes', [])
        )
        
        sec_status = security_report['status']
        if sec_status == "TRUSTED":
            analysis.cert_status = "trusted"
        elif sec_status in ["DANGER", "WARNING", "MISMATCH"]:
            analysis.cert_status = "suspicious"
        else:
            analysis.cert_status = "no_info"

        store_info['security_alerts'] = "\n".join(security_report['alerts'])
        store_info['signature_status'] = sec_status

        # 3. AI PROMPT & GENERATION
        prompt = build_analysis_prompt(payload_dict, store_info)
        
        # --- [NOWE] LOGOWANIE REQUESTU DO PLIKU ---
        log_ai_traffic(package_name, "REQUEST (PROMPT)", prompt)
        # ------------------------------------------

        response = None
        max_retries = 5
        base_delay = 5
        

        async with gemini_lock:
            for attempt in range(max_retries):
                try:
                    response = client.models.generate_content(
                        model='gemini-2.0-flash', 
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type='application/json',
                            response_schema=AiFlatResponse
                        )
                    )

                    await asyncio.sleep(2)
                    break 
                    
                except Exception as api_error:
                    error_str = str(api_error)
                    
                    if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                        if attempt < max_retries - 1:
                            sleep_time = 0
                            # Smart Wait (Regex)
                            retry_match = re.search(r"['\"]retryDelay['\"]:\s*['\"]([\d\.]+)s['\"]", error_str)
                            
                            if retry_match:
                                suggested_wait = float(retry_match.group(1))
                                sleep_time = suggested_wait + 1.0 
                                logger.warning(f"🛑 Google Rate Limit (429). Serwer prosi o {suggested_wait}s przerwy. Czekam {sleep_time:.1f}s...")
                            else:
                                sleep_time = (base_delay * (2 ** attempt)) + random.uniform(0, 1)
                                logger.warning(f"⏳ Google Rate Limit (429). Brak info. Backoff: Czekam {sleep_time:.1f}s...")
                            
                            await asyncio.sleep(sleep_time) # Async sleep!
                            continue
                        else:
                            logger.error("❌ Przekroczono limit prób po błędzie 429.")
                            raise api_error
                    else:
                        raise api_error

        if not response:
            raise Exception("Failed to get response from AI after retries")

        # --- [NOWE] LOGOWANIE ODPOWIEDZI DO PLIKU ---
        log_ai_traffic(package_name, "RESPONSE (RAW JSON)", response.text)
        # --------------------------------------------

        ai_data = json.loads(response.text)
        
        # 4. ZAPIS WYNIKÓW
        analysis.status = "COMPLETED"
        analysis.security_light = ai_data.get("security_score", 3)
        analysis.privacy_light = ai_data.get("privacy_score", 3)
        analysis.short_summary = ai_data.get("short_summary", "")
        
        perm_analysis_data = ai_data.get("permissions_analysis", {})

        analysis.full_report = {
            "security_score": ai_data.get("security_score", 3),
            "privacy_score": ai_data.get("privacy_score", 3),
            "verdict_details": ai_data.get("verdict_details", ""),
            "risk_factors": ai_data.get("risk_factors", []),
            "positive_factors": ai_data.get("positive_factors", []),
            "permissions_analysis": perm_analysis_data,
            "store_info": store_info,
            "security_check": security_report
        }

        db.commit()
        logger.info(f"✅ Finished: {analysis.package_name}")

    except Exception as e:
        logger.error(f"❌ Error for {package_name}: {str(e)}")
        # Logowanie błędu do pliku AI, żeby wiedzieć co poszło nie tak
        log_ai_traffic(package_name, "ERROR", str(e))
        
        try:
            # Ponawiamy sesję w razie rollbacku
            analysis.status = "FAILED"
            analysis.short_summary = f"Error: {str(e)}"
            db.commit()
        except: 
            pass
    finally:
        db.close()