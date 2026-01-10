# app/main.py
import logging
import asyncio
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException, UploadFile, File, Form
from fastapi.security import HTTPBearer
from sqladmin import Admin
from sqlalchemy.orm import Session
from typing import List, Optional

from .database import engine, get_db, SessionLocal
from . import models, schemas, service, auth
from .admin import AppAnalysisAdmin, TrustedVendorAdmin

# --- KONFIGURACJA LOGOWANIA ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("api_logger")

models.Base.metadata.create_all(bind=engine)

# --- GARBAGE COLLECTOR (Sprzątanie zawieszonych zadań) ---

def cleanup_stale_tasks(stale_threshold_minutes: int = 0):
    """
    Czyści zadania PENDING.
    
    Args:
        stale_threshold_minutes (int): 
            0 -> Tryb STARTUP (Czyści wszystko, bo RAM jest pusty).
            >0 -> Tryb PERIODIC (Czyści tylko zadania starsze niż X minut).
    """
    db = SessionLocal()
    try:
        query = db.query(models.AppAnalysis).filter(models.AppAnalysis.status == "PENDING")
        
        # Jeśli to nie jest start systemu, dodajemy filtr czasu
        if stale_threshold_minutes > 0:
            threshold_time = datetime.utcnow() - timedelta(minutes=stale_threshold_minutes)
            # Szukamy zadań utworzonych/aktualizowanych dawniej niż próg
            query = query.filter(models.AppAnalysis.created_at < threshold_time)

        stuck_tasks = query.all()
        
        count = 0
        mode_name = "STARTUP" if stale_threshold_minutes == 0 else "PERIODIC"
        
        for task in stuck_tasks:
            task.status = "FAILED"
            task.short_summary = f"Analiza anulowana (Timeout - {mode_name}). Proszę odświeżyć."
            count += 1
        
        if count > 0:
            db.commit()
            logger.warning(f"🧹 [{mode_name} GC] Wyczyszczono {count} zawieszonych zadań.")
        elif stale_threshold_minutes == 0:
            logger.info(f"✅ [{mode_name} GC] System czysty (brak zawieszonych zadań).")
            
    except Exception as e:
        logger.error(f"❌ [GC ERROR] Błąd czyszczenia: {e}")
    finally:
        db.close()

async def periodic_gc_loop():
    """
    Uruchamia się w tle i co 12 godzin sprawdza stare zadania (starsze niż 60 minut).
    """
    while True:
        try:
            # Czekaj 12 godzin (w sekundach)
            await asyncio.sleep(12 * 3600) 
            
            logger.info("⏰ Uruchamiam cykliczny Garbage Collector...")
            cleanup_stale_tasks(stale_threshold_minutes=60)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"❌ Błąd w pętli GC: {e}")
            await asyncio.sleep(60) # Czekaj chwilę przed ponowną próbą w razie błędu

# --- LIFESPAN (Zarządzanie Start/Stop) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. KOD STARTOWY (Blokujący)
    # Czyścimy wszystko, co wisiało, bo restart serwera zabił procesy w RAM
    cleanup_stale_tasks(stale_threshold_minutes=0)
    
    # 2. URUCHOMIENIE PĘTLI TŁA (Nieblokujące)
    loop_task = asyncio.create_task(periodic_gc_loop())
    
    yield # Tu działa aplikacja...
    
    # 3. ZAMKNIĘCIE (Shutdown)
    loop_task.cancel()
    try:
        await loop_task
    except asyncio.CancelledError:
        pass

# --- INICJALIZACJA APLIKACJI ---
app = FastAPI(title="App Security Analyzer", lifespan=lifespan)

admin = Admin(app, engine)
admin.add_view(AppAnalysisAdmin)
admin.add_view(TrustedVendorAdmin)

# --- ENDPOINTY ---

@app.post("/register", response_model=schemas.Token)
def register_device(payload: schemas.RegisterRequest):
    logger.info(f"📥 [REGISTER] Nowe urządzenie: {payload.uuid}")
    access_token = auth.create_access_token(data={"sub": payload.uuid})
    response_data = {"access_token": access_token, "token_type": "bearer"}
    logger.info(f"📤 [RESPONSE] Token wygenerowany.")
    return response_data

@app.post("/analyze", response_model=schemas.AnalysisResponse)
async def analyze_installed_apps(
    payload: schemas.AnalysisRequest, 
    background_tasks: BackgroundTasks,
    current_user_uuid: str = Depends(auth.get_current_user_uuid),
    db: Session = Depends(get_db)
):
    logger.info(f"📥 [ANALYZE] Request od: {current_user_uuid}, Apek: {len(payload.apps)}")

    results = []
    for app_data in payload.apps:
        # Czyścimy hashe
        if app_data.signing_cert_hashes:
            app_data.signing_cert_hashes = [
                h.replace(":", "").replace(" ", "").upper() for h in app_data.signing_cert_hashes
            ]
            
        record = service.get_or_create_analysis(db, app_data, background_tasks)
        
        # --- LOGIKA NULLOWANIA DLA PENDING ---
        # Jeśli status to PENDING lub NEW, nie chcemy dawać fałszywych zer/false.
        # Chcemy dać NULL, żeby UI pokazało loader.
        # Wyjątek: FAILED też chcemy pokazać (zazwyczaj jako czerwony/szary alert), więc traktujemy jak gotowy.
        
        is_ready = (record.status == "COMPLETED" or record.status == "FAILED")
        
        # Przygotowanie danych, jeśli gotowe
        
        is_in_store_val = False
        if is_ready and record.full_report and "store_info" in record.full_report:
            is_in_store_val = record.full_report["store_info"].get("exists_in_store", False)

        ui_result = schemas.AndroidUiResult(
            # Pola identyfikacyjne (Zawsze obecne)
            package_name=record.package_name,
            app_name=record.app_name if record.app_name else app_data.app_name,
            version_code=record.version_code,
            status=record.status,
            
            # --- Pola z wartością tylko gdy COMPLETED ---
            security_light=record.security_light if is_ready else None,
            privacy_light=record.privacy_light if is_ready else None,
            
            is_up_to_date=record.is_up_to_date if is_ready else None,
            is_in_store=is_in_store_val if is_ready else None,
            
            # downloaded_from_store - decydujemy dać None jeśli pending, żeby UI wczytało się całe naraz
            downloaded_from_store=record.is_from_store if is_ready else None,
            
            is_cert_suspicious=record.cert_status if is_ready else None,
            
            target_sdk_secure=(record.target_sdk >= 26) if (is_ready and record.target_sdk) else None,
            debug_flag_off=(not record.is_debuggable) if is_ready else None,
            has_exported_components=record.has_exported_components if is_ready else None,
            is_fingerprinting_suspected=record.is_fingerprinting_suspected if is_ready else None,
            privacy_policy_exists=record.privacy_policy_exists if is_ready else None,
            
            short_summary=record.short_summary if is_ready else None,
            permissions=record.permissions if (is_ready and record.permissions) else [],
            full_report=record.full_report if is_ready else None
        )
        results.append(ui_result)

    final_response = schemas.AnalysisResponse(results=results)
    
    logger.info(f"RESPONSE:\n{final_response.model_dump_json(indent=2)}")
    
    return final_response

# --- ZAKOMENTOWANY UPLOAD CERT ---
# @app.post("/admin/upload-cert")
# def upload_trusted_cert(
#     vendor_name: str = Form(...),
#     file: UploadFile = File(...),
#     db: Session = Depends(get_db)
# ):
#     content = file.file.read()
#     sha256_hash = ""
#     try:
#         text_content = content.decode('utf-8').strip()
#         clean_text = text_content.replace(":", "").replace(" ", "").upper()
#         if len(clean_text) == 64 and all(c in "0123456789ABCDEF" for c in clean_text):
#             sha256_hash = clean_text
#     except: pass 
#
#     if not sha256_hash:
#         from cryptography import x509
#         from cryptography.hazmat.primitives import hashes
#         try:
#             cert = x509.load_pem_x509_certificate(content)
#             sha256_hash = cert.fingerprint(hashes.SHA256()).hex().upper()
#         except:
#             try:
#                 cert = x509.load_der_x509_certificate(content)
#                 sha256_hash = cert.fingerprint(hashes.SHA256()).hex().upper()
#             except:
#                 raise HTTPException(400, "Niepoprawny format")
#
#     from . import models
#     existing = db.query(