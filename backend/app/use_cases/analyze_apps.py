# app/use_cases/analyze_apps.py
from sqlalchemy.orm import Session
from sqlalchemy import tuple_
from app.infrastructure.database import models # Absolutny
from app import schemas

def execute_analyze_apps(db: Session, apps_payload: list[schemas.AppPayload]) -> list[models.AppAnalysis]:
    """
    Szybka obsługa żądania API.
    Sprawdza bazę, tworzy brakujące rekordy i zleca zadania.
    """
    results = []
    search_keys = []
    payload_map = {}

    for app in apps_payload:
        primary_hash = "UNKNOWN"
        if app.signing_cert_hashes:
            primary_hash = app.signing_cert_hashes[0].replace(":", "").replace(" ", "").upper()
        
        key = (app.package_name, app.version_code, primary_hash)
        search_keys.append(key)
        payload_map[key] = app

    # Masowe sprawdzenie bazy
    existing_analyses = db.query(models.AppAnalysis).filter(
        tuple_(models.AppAnalysis.package_name, models.AppAnalysis.version_code, models.AppAnalysis.signing_cert_hash)\
        .in_(search_keys)
    ).all()

    existing_map = {(a.package_name, a.version_code, a.signing_cert_hash): a for a in existing_analyses}

    for key in search_keys:
        app_data = payload_map[key]
        analysis = existing_map.get(key)

        if not analysis:
            analysis = models.AppAnalysis(
                package_name=app_data.package_name,
                version_code=app_data.version_code,
                signing_cert_hash=key[2],
                app_name=app_data.app_name,
                vendor_name=app_data.vendor,
                is_from_store=app_data.is_from_store,
                is_debuggable=app_data.is_debuggable,
                is_fingerprinting_suspected=app_data.is_fingerprinting_suspected,
                target_sdk=app_data.target_sdk,
                permissions=app_data.permissions,
                libraries=app_data.libraries,
                status="PENDING"
            )
            db.add(analysis)
            db.flush()

            # ZLECENIE ZADANIA DO KOLEJKI
            db.add(models.AnalysisTask(analysis_id=analysis.id, status="PENDING"))
        
        elif analysis.status == "FAILED":
            analysis.status = "PENDING"

        results.append(analysis)

    db.commit()
    return results