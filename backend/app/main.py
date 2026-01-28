import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from sqladmin import Admin

# --- IMPORTY WEWNĘTRZNE (ZGODNE Z NOWĄ STRUKTURĄ) ---
from app.infrastructure.database.database import engine, get_db, SessionLocal
from app.infrastructure.database import models
from . import schemas, auth
from app.admin import (
    AppAnalysisAdmin, 
    TrustedVendorAdmin, 
    AnalysisTaskAdmin, 
    authentication_backend
)
# Use Cases
from app.use_cases.analyze_apps import execute_analyze_apps
from app.use_cases.task_processor import process_pending_tasks

# --- KONFIGURACJA LOGOWANIA ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("api_logger")

# Inicjalizacja tabelek (jeśli nie używasz migracji Alembic)
models.Base.metadata.create_all(bind=engine)

# --- LIFESPAN (ZARZĄDZANIE STARTEM I STOPEM) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. CZYSZCZENIE STARTOWE
    # Odblokowujemy zadania, które mogły utknąć w statusie PROCESSING przez restart serwera
    db = SessionLocal()
    try:
        stuck_tasks = db.query(models.AnalysisTask).filter(models.AnalysisTask.status == "PROCESSING").all()
        if stuck_tasks:
            for t in stuck_tasks:
                t.status = "PENDING"
                t.locked_at = None
            db.commit()
            logger.warning(f"🧹 Odblokowano {len(stuck_tasks)} zadań po restarcie.")
    finally:
        db.close()
    
    # 2. URUCHOMIENIE WORKERA KOLEJKI (W TLE)
    import asyncio
    worker_task = asyncio.create_task(process_pending_tasks())
    
    yield # --- TU DZIAŁA APLIKACJA ---
    
    # 3. SHUTDOWN
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        logger.info("🛑 Worker kolejki został pomyślnie zatrzymany.")

# --- INICJALIZACJA APLIKACJI ---
app = FastAPI(title="App Security Analyzer - Clean Arch", lifespan=lifespan)

# Klucz sesji dla Admina (fallback dla dev)
secret_key = os.getenv("SECRET_KEY", "dev-secret-12345")

app.add_middleware(
    SessionMiddleware, 
    secret_key=secret_key,
    https_only=False,
    same_site="lax",
    max_age=3600,
    session_cookie="security_session"
)

# --- PANEL ADMINISTRATORA ---
admin = Admin(app, engine, authentication_backend=authentication_backend)
admin.add_view(AppAnalysisAdmin)
admin.add_view(TrustedVendorAdmin)
admin.add_view(AnalysisTaskAdmin) # Widok nowej kolejki zadań

# --- ENDPOINTY ---

@app.post("/register", response_model=schemas.Token)
def register_device(payload: schemas.RegisterRequest):
    """
    Rejestracja urządzenia i wydanie tokenu (Mock/Uproszczone).
    """
    logger.info(f"📥 [REGISTER] Nowe urządzenie: {'TEST'}")
    access_token = auth.create_access_token(data={"sub": payload.uuid})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/analyze", response_model=schemas.AnalysisResponse)
async def analyze_installed_apps(
    payload: schemas.AnalysisRequest, 
    db: Session = Depends(get_db)
):
    """
    ASYNC REQUEST-REPLY:
    Przyjmuje listę apek, sprawdza bazę, zleca brakujące zadania i natychmiast odpowiada.
    """
    # 1. Wywołanie Logiki Biznesowej (Use Case)
    analysis_records = execute_analyze_apps(db, payload.apps)

    results = []
    
    # 2. Mapowanie rekordów bazy na format UI
    for record in analysis_records:
        is_ready = (record.status == "COMPLETED")
        
        # Wyciąganie danych AI (EncryptedJSON deszyfruje się automatycznie)
        ai_data = record.full_report if (is_ready and record.full_report) else {}
        
        # Logika statusu producenta (Vendor Status)
        vendor_ui_status = "no_negative_data"
        if is_ready:
            if record.cert_status == "trusted":
                vendor_ui_status = "verified"
            elif record.cert_status == "suspicious":
                vendor_ui_status = "suspected"

        # Budowanie odpowiedzi dla konkretnej apki
        ui_result = schemas.AndroidUiResult(
            package_name=record.package_name,
            app_name=record.app_name if record.app_name else "Nieznana",
            version_code=record.version_code,
            status=record.status,
            
            security_light=record.security_light if is_ready else None,
            privacy_light=record.privacy_light if is_ready else None,
            short_summary=record.short_summary if is_ready else "Analiza w toku...",

            # Flagi techniczne
            target_sdk_secure=(record.target_sdk >= 31) if (is_ready and record.target_sdk) else None,
            downloaded_from_store=record.is_from_store,
            debug_flag_off=(not record.is_debuggable) if is_ready else None,
            has_exported_components=record.has_exported_components,
            is_fingerprinting_suspected=record.is_fingerprinting_suspected,
            privacy_policy_exists=record.privacy_policy_exists,
            vendor_status=vendor_ui_status,
            
            permissions=record.permissions if record.permissions else [],

            # Szczegółowy raport AI (zgodnie z nowym botem)
            full_report=schemas.AiReportDetails(
                security_score=record.security_light or 0,
                privacy_score=record.privacy_light or 0,
                short_summary=record.short_summary or "",
                verdict_details=ai_data.get("verdict_details", ""),
                risk_factors=ai_data.get("risk_factors", []),
                positive_factors=ai_data.get("positive_factors", []),
                trackers=ai_data.get("trackers", []),
                permissions_analysis=ai_data.get("permissions_analysis", {
                    "dangerous_count": 0,
                    "summary": "Oczekiwanie na analizę..."
                })
            ) if is_ready else None
        )
        results.append(ui_result)
    logger.info(f"📊 [ANALYZE] Zwrócono wyniki dla {len(results)} aplikacji.")
    logger.info(results)
    return schemas.AnalysisResponse(results=results)

@app.get("/health")
def health_check():
    return {"status": "ok", "architecture": "clean-arch", "worker": "active"}