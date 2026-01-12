# app/main.py
import logging
import asyncio
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException, UploadFile, File, Form
from fastapi.security import HTTPBearer
from sqladmin import Admin
from sqlalchemy.orm import Session
from typing import List, Optional
from starlette.middleware.sessions import SessionMiddleware # <--- IMPORT

import os

from .database import engine, get_db, SessionLocal
from . import models, schemas, service, auth
from .admin import AppAnalysisAdmin, TrustedVendorAdmin, authentication_backend # <--- IMPORT AUTH
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
secret_key = os.getenv("SECRET_KEY")

if not secret_key:
    # Zabezpieczenie: Jeśli zapomnisz dodać klucz do .env, aplikacja krzyknie błędem (w logach),
    # zamiast działać na domyślnym, słabym haśle.
    logger.warning("⚠️ BRAK SECRET_KEY W .ENV! Używam niebezpiecznego domyślnego klucza.")

app.add_middleware(
    SessionMiddleware, 
    secret_key=secret_key,
    https_only=False,       # <--- WYMUSZA FLAGĘ SECURE (Wymagane przy HTTPS)
    same_site="lax",       # <--- Pozwala na działanie ciasteczka przy przekierowaniach
    max_age=3600,           # <--- Sesja ważna przez godzinę (opcjonalnie)
    session_cookie="session_v4"
)
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

# app/main.py (Fragment - tylko funkcja analyze)

@app.post("/analyze", response_model=schemas.AnalysisResponse)
async def analyze_installed_apps(
    payload: schemas.AnalysisRequest, 
    background_tasks: BackgroundTasks,
    current_user_uuid: str = Depends(auth.get_current_user_uuid),
    db: Session = Depends(get_db)
):
    logger.info(f"📥 [ANALYZE] Request od: {current_user_uuid}, Apek: {len(payload.apps)}")

    # 1. Wstępne czyszczenie hashy
    for app_data in payload.apps:
        if app_data.signing_cert_hashes:
            app_data.signing_cert_hashes = [
                h.replace(":", "").replace(" ", "").upper() for h in app_data.signing_cert_hashes
            ]

    # 2. BATCH PROCESSING
    analysis_map = service.get_or_create_batch_analysis(db, payload.apps, background_tasks)

    results = []
    
    # 3. Budowanie odpowiedzi (Z NOWĄ LOGIKĄ)
    for app_data in payload.apps:
        record = analysis_map.get(app_data.package_name)
        
        if not record:
            continue

        is_ready = (record.status == "COMPLETED" or record.status == "FAILED")
        
        # A. Logika Vendor Status (Dla UI)
        vendor_ui_status = "no_negative_data"
        if is_ready:
            if record.cert_status == "trusted":
                vendor_ui_status = "verified"
            elif record.cert_status == "suspicious":
                vendor_ui_status = "suspected"

        # B. Wyciąganie danych AI z full_report
        # (Dzięki EncryptedJSON w models.py, record.full_report jest już słownikiem Pythonowym)
        ai_data = {}
        store_exists = False
        if is_ready and record.full_report:
            ai_data = record.full_report
            if "store_info" in record.full_report:
                store_exists = record.full_report["store_info"].get("exists_in_store", False)

        # C. Konstrukcja obiektu UI
        ui_result = schemas.AndroidUiResult(
            package_name=record.package_name,
            app_name=record.app_name if record.app_name else app_data.app_name,
            version_code=record.version_code,
            status=record.status,
            
            # --- Oceny i Treści ---
            security_score=ai_data.get("security_score") if is_ready else None,
            privacy_score=ai_data.get("privacy_score") if is_ready else None,
            # Zachowujemy security_light mapując score na 1-3 jeśli potrzebne, lub biorąc z bazy
            security_light=record.security_light if is_ready else None,
            privacy_light=record.privacy_light if is_ready else None,
            short_summary=record.short_summary if is_ready else None,

            # --- Flagi Techniczne (Code Logic) ---
            target_sdk_secure=(record.target_sdk >= 30) if (is_ready and record.target_sdk) else None,
            is_in_store=store_exists if is_ready else None,
            downloaded_from_store=record.is_from_store if is_ready else None,
            # is_debuggable: True to źle, ale UI prosiło o flagę "debug_flag_off" (czyli True to dobrze)
            debug_flag_off=(not record.is_debuggable) if is_ready else None,
            has_exported_components=record.has_exported_components if is_ready else None,
            is_fingerprinting_suspected=record.is_fingerprinting_suspected if is_ready else None,
            privacy_policy_exists=record.privacy_policy_exists if is_ready else None,
            
            is_cert_suspicious=record.cert_status if is_ready else None,
            vendor_status=vendor_ui_status if is_ready else None,

            permissions=record.permissions if (is_ready and record.permissions) else [],

            # --- Detale Raportu ---
            full_report=schemas.AiReportDetails(
                verdict_details=ai_data.get("verdict", "Brak danych"), # Uwaga: w service.py zapisujesz to jako 'verdict'
                risk_factors=ai_data.get("risk_factors", []),
                positive_factors=ai_data.get("positive_factors", []),
                permissions_analysis=ai_data.get("permissions_analysis", {}), # Może być w AI jsonie lub nie, zależnie od promptu
                trackers=ai_data.get("trackers", [])
            ) if (is_ready and "verdict" in ai_data) else None
        )
        results.append(ui_result)

    final_response = schemas.AnalysisResponse(results=results)
    return final_response



@app.get("/health")
def health_check():
    return {"status": "ok"}

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