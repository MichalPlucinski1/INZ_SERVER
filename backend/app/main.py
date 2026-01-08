from fastapi import FastAPI, Depends, BackgroundTasks
from sqladmin import Admin
from sqlalchemy.orm import Session
from typing import List

from .database import engine, get_db
from . import models, schemas, service
from .admin import AppAnalysisAdmin, TrustedVendorAdmin

from fastapi import UploadFile, File, HTTPException
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# Tworzenie tabel
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="App Security Analyzer")

# Admin Panel
admin = Admin(app, engine)
admin.add_view(AppAnalysisAdmin)
admin.add_view(TrustedVendorAdmin)

@app.post("/analyze", response_model=schemas.AnalysisResponse)
def analyze_installed_apps(
    payload: schemas.AnalysisRequest, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    results = []
    
    for app_data in payload.apps:
        # 1. Pobieramy/Tworzymy analizę
        analysis_record = service.get_or_create_analysis(db, app_data, background_tasks)
        
        # 2. MAPOWANIE (Tutaj był błąd - musimy przypisać odpowiednie kolumny)
        result_item = schemas.AppAnalysisResult(
            package_name=analysis_record.package_name,
            status=analysis_record.status,
            
            # Przepisujemy kolumny z bazy na pola JSON-a:
            security_light=analysis_record.security_light,
            privacy_light=analysis_record.privacy_light,
            
            # UWAGA: W bazie 'short_summary', w JSON 'summary'
            summary=analysis_record.short_summary, 
            
            # UWAGA: W bazie 'full_report', w JSON 'details'
            details=analysis_record.full_report
        )
        results.append(result_item)

    return schemas.AnalysisResponse(results=results)


@app.post("/admin/upload-cert")
def upload_trusted_cert(
    vendor_name: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Wgraj plik certyfikatu (.crt/.der) LUB plik tekstowy (.txt) zawierający hash.
    System wyliczy SHA-256 i doda do zaufanych.
    """
    content = file.file.read()
    sha256_hash = ""
    
    # Scenariusz A: Plik tekstowy z hashem (np. skopiowany z APKMirror)
    try:
        text_content = content.decode('utf-8').strip()
        # Prosta walidacja czy to wygląda na hash (HEX)
        clean_text = text_content.replace(":", "").replace(" ", "").upper()
        # SHA256 ma 64 znaki
        if len(clean_text) == 64 and all(c in "0123456789ABCDEF" for c in clean_text):
            sha256_hash = clean_text
    except:
        pass # To nie był tekst, próbujemy jako binarny certyfikat

    # Scenariusz B: Plik certyfikatu (X.509)
    if not sha256_hash:
        try:
            # Próba PEM (tekstowy certyfikat)
            cert = x509.load_pem_x509_certificate(content)
            sha256_hash = cert.fingerprint(hashes.SHA256()).hex().upper()
        except:
            try:
                # Próba DER (binarny certyfikat)
                cert = x509.load_der_x509_certificate(content)
                sha256_hash = cert.fingerprint(hashes.SHA256()).hex().upper()
            except:
                raise HTTPException(400, "Nie rozpoznano formatu pliku (ani txt z hashem, ani cert X.509)")

    # Zapis do bazy
    from . import models # Import wewnątrz, żeby uniknąć cykli
    
    existing = db.query(models.TrustedVendor).filter(models.TrustedVendor.known_cert_hash == sha256_hash).first()
    if existing:
        return {"message": "Już istnieje", "vendor": existing.vendor_name}

    new_vendor = models.TrustedVendor(
        vendor_name=vendor_name,
        known_cert_hash=sha256_hash,
        trust_level="VERIFIED"
    )
    db.add(new_vendor)
    db.commit()

    return {"message": "Dodano zaufanego dostawcę", "hash": sha256_hash, "vendor": vendor_name}