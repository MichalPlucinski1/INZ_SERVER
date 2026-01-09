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

# Importy naszych modułów pomocniczych
from .scraper import scrape_google_play 
from .prompt_manager import build_analysis_prompt
# ZMIANA: Importujemy nową funkcję do sprawdzania vendora i historii
from .security import check_security_alerts

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
        # Retry logic: Jeśli analiza jest FAILED lub "Pusta" (0), ponów ją
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
        logger.info(f"🤖 [Worker] Start analizy ID: {analysis_id}")
        
        analysis = db.query(models.AppAnalysis).filter(models.AppAnalysis.id == analysis_id).first()
        if not analysis:
            return

        # --- KROK 1: SCRAPING (Oczy systemu) ---
        store_info = scrape_google_play(
            package_name=payload_dict.get('package_name'),
            user_version_name=payload_dict.get('version_name')
        )
        
        # --- KROK 2: SECURITY CHECKS (Vendor + Historia) ---
        # Tutaj następuje weryfikacja czy 'vendor' z Androida pasuje do hasha w bazie
        security_report = check_security_alerts(
            db, 
            package_name=payload_dict.get('package_name'),
            claimed_vendor=payload_dict.get('vendor'), # <-- Pobieramy pole 'vendor' z JSONa Androida
            incoming_hashes=payload_dict.get('signing_cert_hashes', [])
        )
        
        # Przygotowanie tekstu alertów dla AI
        security_context_str = "\n".join(security_report['alerts'])
        if not security_context_str:
            security_context_str = "Brak ostrzeżeń dotyczących podpisu cyfrowego (Status: OK)."

        # Wstrzykujemy wynik weryfikacji do obiektu store_info.
        # Dzięki temu trafi on do promptu automatycznie przez prompt_manager.
        store_info['security_alerts'] = security_context_str
        store_info['signature_status'] = security_report['status']

        # --- KROK 3: BUDOWANIE PROMPTU ---
        prompt = build_analysis_prompt(
            device_data=payload_dict, 
            store_data=store_info
        )
        
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
            "store_verification": store_info, # Zawiera teraz też dane o podpisie
            "ai_signature_verdict": security_report['status'] # Dodatkowy ślad w bazie
        }

        db.commit()
        logger.info(f"✅ Analiza zakończona dla {payload_dict.get('package_name')}")

    except Exception as e:
        logger.error(f"❌ Błąd workera: {str(e)}")
        try:
            analysis.status = "FAILED"
            analysis.short_summary = f"Error: {str(e)}"
            db.commit()
        except:
            pass
    finally:
        db.close()