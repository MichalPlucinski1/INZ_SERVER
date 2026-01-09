# app/main.py
import logging
from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException, UploadFile, File, Form
from fastapi.security import HTTPBearer # Import potrzebny, choć używany w auth.py, to tu spinamy całość
from sqladmin import Admin
from sqlalchemy.orm import Session
from typing import List

from .database import engine, get_db
from . import models, schemas, service, auth
from .admin import AppAnalysisAdmin, TrustedVendorAdmin

# --- KONFIGURACJA LOGOWANIA ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("api_logger")

# Tworzenie tabel
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="App Security Analyzer")

# Admin Panel
admin = Admin(app, engine)
admin.add_view(AppAnalysisAdmin)
admin.add_view(TrustedVendorAdmin)

# --- 1. ENDPOINT REJESTRACJI ---
@app.post("/register", response_model=schemas.Token)
def register_device(payload: schemas.RegisterRequest):
    logger.info(f"📥 [REGISTER] Nowe urządzenie: {payload.uuid}")
    
    access_token = auth.create_access_token(
        data={"sub": payload.uuid}
    )
    
    response_data = {"access_token": access_token, "token_type": "bearer"}
    logger.info(f"📤 [RESPONSE] Token wygenerowany dla {payload.uuid}")
    return response_data

# --- 2. ENDPOINT ANALIZY ---
@app.post("/analyze", response_model=schemas.AnalysisResponse)
async def analyze_installed_apps(
    payload: schemas.AnalysisRequest, 
    background_tasks: BackgroundTasks,
    current_user_uuid: str = Depends(auth.get_current_user_uuid),
    db: Session = Depends(get_db)
):
    # Logowanie przychodzącego requestu (opcjonalne, skrócone info)
    logger.info(f"📥 [ANALYZE] Request od: {current_user_uuid}, Liczba apek: {len(payload.apps)}")

    results = []
    for app_data in payload.apps:
        # Czyścimy hashe (safety first)
        if app_data.signing_cert_hashes:
            app_data.signing_cert_hashes = [
                h.replace(":", "").replace(" ", "").upper() for h in app_data.signing_cert_hashes
            ]
            
        analysis_record = service.get_or_create_analysis(db, app_data, background_tasks)
        
        result_item = schemas.AppAnalysisResult(
            package_name=analysis_record.package_name,
            status=analysis_record.status,
            security_light=analysis_record.security_light,
            privacy_light=analysis_record.privacy_light,
            summary=analysis_record.short_summary,
            details=analysis_record.full_report
        )
        results.append(result_item)

    # Budujemy obiekt odpowiedzi
    final_response = schemas.AnalysisResponse(results=results)
    
    # --- LOGOWANIE ODPOWIEDZI ---
    # model_dump_json(indent=2) sprawi, że w logach zobaczysz piękny, sformatowany JSON
    logger.info(f"📤 [RESPONSE] Wysyłam do Androida:\n{final_response.model_dump_json(indent=2)}")
    
    return final_response

# --- 3. ENDPOINT UPLOADU ---
@app.post("/admin/upload-cert")
def upload_trusted_cert(
    vendor_name: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    content = file.file.read()
    sha256_hash = ""
    
    # 1. Próba jako tekst
    try:
        text_content = content.decode('utf-8').strip()
        clean_text = text_content.replace(":", "").replace(" ", "").upper()
        if len(clean_text) == 64 and all(c in "0123456789ABCDEF" for c in clean_text):
            sha256_hash = clean_text
    except:
        pass 

    # 2. Próba jako certyfikat
    if not sha256_hash:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        try:
            cert = x509.load_pem_x509_certificate(content)
            sha256_hash = cert.fingerprint(hashes.SHA256()).hex().upper()
        except:
            try:
                cert = x509.load_der_x509_certificate(content)
                sha256_hash = cert.fingerprint(hashes.SHA256()).hex().upper()
            except:
                raise HTTPException(400, "Niepoprawny format (ani hash txt, ani cert X.509)")

    # Zapis
    from . import models
    existing = db.query(models.TrustedVendor).filter(models.TrustedVendor.known_cert_hash == sha256_hash).first()
    
    if existing:
        return {"message": "Certyfikat już istnieje", "vendor": existing.vendor_name}

    new_vendor = models.TrustedVendor(
        vendor_name=vendor_name,
        known_cert_hash=sha256_hash,
        trust_level="VERIFIED"
    )
    db.add(new_vendor)
    db.commit()
    
    logger.info(f"🛡️ [ADMIN] Dodano certyfikat dla {vendor_name}: {sha256_hash}")
    return {"message": "Dodano zaufanego dostawcę", "hash": sha256_hash, "vendor": vendor_name}