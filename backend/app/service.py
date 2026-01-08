# app/service.py
import os
import json
import logging
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List

from . import models, schemas
from .database import SessionLocal
# NOWOŚĆ: Importujemy nasz scraper
from .scraper import scrape_google_play 
from .prompt_manager import build_analysis_prompt
from .security import verify_app_signature

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

# --- Modele dla AI (Structured Output) ---
class AiFlatResponse(BaseModel):
    security_score: int = Field(description="Ocena bezpieczeństwa: 1=Bezpieczna (Zielone), 2=Ostrzeżenie (Żółte), 3=Krytyczne (Czerwone)")
    privacy_score: int = Field(description="Ocena prywatności: 1=Dobra, 2=Średnia, 3=Zła")
    short_summary: str = Field(description="Jedno zdanie podsumowania po polsku")
    verdict_details: str = Field(description="Szczegółowy werdykt techniczny")
    risk_factors: List[str] = Field(description="Lista konkretnych zagrożeń")
    positive_factors: List[str] = Field(description="Lista pozytywnych aspektów")

# ----------------------------------------------------

def get_or_create_analysis(db: Session, app_payload: schemas.AppPayload, background_tasks):
    primary_hash = app_payload.signing_cert_hashes[0] if app_payload.signing_cert_hashes else "UNKNOWN"

    existing_analysis = db.query(models.AppAnalysis).filter(
        models.AppAnalysis.package_name == app_payload.package_name,
        models.AppAnalysis.version_code == app_payload.version_code,
        models.AppAnalysis.signing_cert_hash == primary_hash
    ).first()

    if existing_analysis:
        # Retry logic
        if existing_analysis.status == "FAILED" or (existing_analysis.status == "COMPLETED" and existing_analysis.security_light == 0):
            logger.info(f"🔄 RETRY: Ponawiam analizę dla {app_payload.package_name}")
            existing_analysis.status = "PENDING"
            db.commit()
            background_tasks.add_task(run_ai_analysis_worker, existing_analysis.id, app_payload.model_dump())
            return existing_analysis
        
        logger.info(f"✅ HIT: Znaleziono analizę dla {app_payload.package_name}")
        return existing_analysis

    logger.info(f"🆕 MISS: Tworzenie zlecenia dla {app_payload.package_name}")
    new_analysis = models.AppAnalysis(
        package_name=app_payload.package_name,
        version_code=app_payload.version_code,
        signing_cert_hash=primary_hash,
        app_name=app_payload.app_name,
        version_name=app_payload.version_name,
        is_from_store=app_payload.is_from_store,
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
        logger.info(f"[Worker] Start analizy ID: {analysis_id}")
        
        analysis = db.query(models.AppAnalysis).filter(models.AppAnalysis.id == analysis_id).first()
        if not analysis:
            return
        
        

        # --- KROK 1: SCRAPING ---
        store_info = scrape_google_play(
            package_name=payload_dict.get('package_name'),
            user_version_name=payload_dict.get('version_name')
        )
        # --- KROK 2: WERYFIKACJA PODPISU CYFROWEGO ---
        sig_verification = verify_app_signature(
            db, 
            payload_dict.get('package_name'), 
            payload_dict.get('signing_cert_hashes')
        )

        trust_context = ""
        if sig_verification['status'] == "TRUSTED":
            trust_context = f"Aplikacja jest cyfrowo podpisana przez zweryfikowanego producenta: {sig_verification['vendor_name']}."
        else:
            trust_context = "Podpis cyfrowy nie jest w bazie, nie możemy go sprawdzić (traktuj jako neutralny)."

        store_info['signature_verification'] = trust_context
        
        # --- KROK 3: BUDOWANIE PROMPTU (TERAZ CZYSTO!) ---
        # delegujemy do prompt_manager.py
        prompt = build_analysis_prompt(
            device_data=payload_dict, 
            store_data=store_info
        )

        # Log fragment promptu dla pewności
        # logger.info(f"Prompt Preview: {prompt[:200]}...")

        # --- KROK 4: AI GENERATION ---
        response = client.models.generate_content(
            model='gemini-2.0-flash', 
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type='application/json',
                response_schema=AiFlatResponse
            )
        )
        
        ai_data = json.loads(response.text)
        
        # --- KROK 5: ZAPIS ---
        analysis.status = "COMPLETED"
        analysis.security_light = ai_data.get("security_score", 0)
        analysis.privacy_light = ai_data.get("privacy_score", 0)
        analysis.short_summary = ai_data.get("short_summary", "")
        
        analysis.full_report = {
            "verdict": ai_data.get("verdict_details"),
            "risk_factors": ai_data.get("risk_factors", []),
            "positive_factors": ai_data.get("positive_factors", []),
            # Zapisujemy też wynik scrapera w raporcie, żeby mieć ślad w bazie
            "store_verification": store_info 
        }

        db.commit()
        logger.info(f"Analiza zakończona dla {payload_dict.get('package_name')}")

    except Exception as e:
        logger.error(f"Błąd workera: {str(e)}")
        try:
            analysis.status = "FAILED"
            analysis.short_summary = f"Error: {str(e)}"
            db.commit()
        except:
            pass
    finally:
        db.close()