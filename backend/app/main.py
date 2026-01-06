import uuid
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import BigInteger
from sqladmin import Admin, ModelView

from .database import engine, Base, get_db, init_db_data
from .models import Application, Category, CveDefinition, PermissionRule, Severity, AppVersion
from .schemas import ScanRequest, ScanResponse, AppScanResult, SecurityStatus, PrivacyStatus

# 1. Tworzenie tabel w bazie danych (automatyczna migracja przy starcie)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Security Analyzer API",
    version="2.0.0",
    description="System analizy bezpieczeństwa Androida (Inżynierka)"
)

# --- KONFIGURACJA PANELU ADMINA (SQLAdmin) ---
admin = Admin(app, engine)

# Definiujemy klasy widoków (To naprawia Twój błąd)
class ApplicationAdmin(ModelView, model=Application):
    column_list = [Application.package_name, Application.app_name, Application.vendor]
    icon = "fa-solid fa-mobile"

class AppVersionAdmin(ModelView, model=AppVersion):
    column_list = [AppVersion.package_name, AppVersion.version_code, AppVersion.analyzed_at]
    icon = "fa-solid fa-code-branch"

class CategoryAdmin(ModelView, model=Category):
    column_list = [Category.name, Category.description]
    icon = "fa-solid fa-layer-group"

class RuleAdmin(ModelView, model=PermissionRule):
    column_list = [PermissionRule.category, PermissionRule.permission_name, PermissionRule.severity]
    icon = "fa-solid fa-scale-balanced"

class CveAdmin(ModelView, model=CveDefinition):
    column_list = [CveDefinition.cve_id, CveDefinition.cvss_score]
    icon = "fa-solid fa-shield-virus"

# Rejestracja widoków
admin.add_view(ApplicationAdmin)
admin.add_view(AppVersionAdmin)
admin.add_view(CategoryAdmin)
admin.add_view(RuleAdmin)
admin.add_view(CveAdmin)

# --- ENDPOINTY API ---

# --- EVENT STARTOWY (SEED) ---
@app.on_event("startup")
def startup_event():
    db = next(get_db())
    init_db_data(db)

# --- Mock test ---
@app.post("/api/mock", response_model=ScanResponse)
async def scan_apps(request: ScanRequest):
    """
    Główny endpoint skanujący.
    Przyjmuje listę aplikacji z Androida -> Zwraca ocenę ryzyka.
    """
    results = []

    # Iterujemy po aplikacjach przesłanych przez telefon
    for app_data in request.apps:
        
        # --- SYMULACJA LOGIKI (MOCK) ---
        # Tutaj w przyszłości będzie zapytanie do Bazy Danych!
        
        # Scenariusz 1: Wykrywamy "złą" aplikację (np. testowo Facebook)
        if "facebook" in app_data.package_name.lower():
            sec_status = "RED"
            sec_desc = "Znaleziono krytyczne podatności CVE-2023-XYZ"
            priv_status = "YELLOW"
            priv_desc = "Duża liczba uprawnień śledzących"
        
        # Scenariusz 2: Aplikacja bezpieczna
        else:
            sec_status = "GREEN"
            sec_desc = "Brak znanych zagrożeń"
            priv_status = "GREEN"
            priv_desc = "Uprawnienia wyglądają w porządku"

        # Budowanie odpowiedzi dla pojedynczej aplikacji
        result = AppScanResult(
            package_name=app_data.package_name,
            security=SecurityStatus(
                status_light=sec_status,
                description=sec_desc,
                cve_count=1 if sec_status == "RED" else 0,
                max_cvss=9.8 if sec_status == "RED" else 0.0
            ),
            privacy=PrivacyStatus(
                status_light=priv_status,
                description=priv_desc,
                violation_count=0,
                risky_permissions=[]
            )
        )
        results.append(result)

    # Zwracamy zbiorczy raport
    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        results=results
    )


@app.post("/api/scan", response_model=ScanResponse)
async def scan_apps(request: ScanRequest, db: Session = Depends(get_db)):
    results = []

    for app_payload in request.apps:
        # 1. Znajdź lub utwórz Aplikację (baza wiedzy o pakiecie)
        db_app = db.query(Application).filter(Application.package_name == app_payload.package_name).first()
        
        if not db_app:
            # Rejestrujemy nową aplikację (bez kategorii na razie)
            db_app = Application(
                package_name=app_payload.package_name,
                app_name=app_payload.app_name
            )
            db.add(db_app)
            db.commit()
            db.refresh(db_app)

        # 2. Znajdź lub utwórz Wersję (historia zmian)
        db_version = db.query(AppVersion).filter(
            AppVersion.package_name == app_payload.package_name,
            AppVersion.version_code == app_payload.version_code
        ).first()

        if not db_version:
            # To nowa wersja tej apki! Zapiszmy jej uprawnienia.
            db_version = AppVersion(
                package_name=db_app.package_name,
                version_code=app_payload.version_code,
                version_name=app_payload.version_name,
                permissions_snapshot=app_payload.permissions # Zapisujemy listę jako JSON
            )
            db.add(db_version)
            db.commit()
        
        # 3. Logika Oceny (Privacy Engine)
        violations = []
        privacy_light = "GREEN"
        privacy_desc = "Ok"

        # Sprawdzamy reguły TYLKO jeśli aplikacja ma przypisaną kategorię
        if db_app.category:
            rules = db.query(PermissionRule).filter(PermissionRule.category_id == db_app.category.id).all()
            
            # Pobieramy uprawnienia z payloadu (lub z bazy wersji)
            current_perms = app_payload.permissions

            for rule in rules:
                if rule.permission_name in current_perms:
                    msg = f"[{rule.severity}] {rule.risk_message}"
                    violations.append(msg)
            
            if violations:
                privacy_light = "RED" if any("CRITICAL" in v for v in violations) else "YELLOW"
                privacy_desc = f"Znaleziono {len(violations)} naruszeń."
        else:
            privacy_light = "GRAY"
            privacy_desc = "Aplikacja nieznana (brak kategorii)."

        # 4. Logika CVE (Placeholder - tu wepniemy API w kolejnym kroku)
        sec_light = "GREEN"
        
        # Budowa wyniku
        results.append(AppScanResult(
            package_name=app_payload.package_name,
            security=SecurityStatus(
                status_light=sec_light, description="Brak danych CVE", cve_count=0, max_cvss=0.0
            ),
            privacy=PrivacyStatus(
                status_light=privacy_light, description=privacy_desc, violation_count=len(violations), risky_permissions=violations
            )
        ))

    return ScanResponse(scan_id=str(uuid.uuid4()), results=results)


@app.get("/")
def read_root():
    return {"status": "System działa poprawnie", "docs": "/docs", "admin": "/admin"}