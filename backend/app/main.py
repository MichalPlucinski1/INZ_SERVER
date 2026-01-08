from fastapi import FastAPI, Depends, BackgroundTasks
from sqladmin import Admin
from sqlalchemy.orm import Session
from typing import List

from .database import engine, get_db
from . import models, schemas, service
from .admin import AppAnalysisAdmin, TrustedVendorAdmin

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