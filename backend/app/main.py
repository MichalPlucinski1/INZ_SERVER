import uuid
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqladmin import Admin, ModelView

from .database import engine, Base, get_db, init_db_data
from .models import Application, Category, CveDefinition, PermissionRule, Severity
from .schemas import ScanRequest, ScanResponse, AppScanResult, SecurityStatus, PrivacyStatus

# 1. Tworzenie tabel w bazie danych (automatyczna migracja przy starcie)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Security Analyzer API",
    version="1.0.0",
    description="System analizy bezpieczeństwa Androida (Inżynierka)"
)

# --- KONFIGURACJA PANELU ADMINA (SQLAdmin) ---
admin = Admin(app, engine)

# Widoki tabel w panelu admina
class AppView(ModelView, model=Application):
    column_list = [Application.package_name, Application.app_name]

class CategoryView(ModelView, model=Category):
    column_list = [Category.name, Category.description]

class CveView(ModelView, model=CveDefinition):
    column_list = [CveDefinition.cve_id, CveDefinition.cvss_score]

class RuleView(ModelView, model=PermissionRule):
    column_list = [PermissionRule.category, PermissionRule.permission_name, PermissionRule.severity]

# Rejestracja widoków
admin.add_view(AppView)
admin.add_view(CategoryView)
admin.add_view(CveView)
admin.add_view(RuleView)

# --- ENDPOINTY API ---

# --- EVENT STARTOWY (SEED) ---
@app.on_event("startup")
def startup_event():
    # Tworzymy nową sesję tylko do inicjalizacji
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

    for app_data in request.apps:
        # 1. Szukamy aplikacji w naszej bazie wiedzy
        # (Musimy wiedzieć, czy to "Gra" czy "Narzędzie")
        db_app = db.query(Application).filter(Application.package_name == app_data.package_name).first()
        
        # Domyślne statusy (na start optymistyczne)
        privacy_light = "GREEN"
        privacy_desc = "Brak zastrzeżeń."
        violations = []
        warning_count = 0
        critical_count = 0

        # --- LOGIKA UPRAWNIEŃ (PRIVACY ENGINE) ---
        if db_app and db_app.categories:
            # Dla każdej kategorii tej aplikacji (np. UTILITY)
            for category in db_app.categories:
                # Pobierz reguły dla tej kategorii
                rules = db.query(PermissionRule).filter(PermissionRule.category_id == category.id).all()
                
                for rule in rules:
                    # Czy aplikacja na telefonie ma zakazane uprawnienie?
                    # Porównujemy nazwy uprawnień (np. android.permission.CAMERA)
                    if rule.permission_name in app_data.permissions:
                        # MAMY NARUSZENIE!
                        if rule.severity == Severity.CRITICAL:
                            critical_count += 1
                            violations.append(f"[CRITICAL] {rule.risk_message}")
                        else:
                            warning_count += 1
                            violations.append(f"[WARNING] {rule.risk_message}")

            # Algorytm Oceny (Scoring)
            if critical_count > 0:
                privacy_light = "RED"
                privacy_desc = f"Wykryto {critical_count} krytycznych naruszeń prywatności!"
            elif warning_count >= 2: # Np. 2 ostrzeżenia = Czerwony
                 privacy_light = "RED"
                 privacy_desc = f"Wiele pomniejszych naruszeń ({warning_count})."
            elif warning_count > 0:
                privacy_light = "YELLOW"
                privacy_desc = "Znaleziono potencjalne zagrożenia."
        
        else:
            # Nie znamy tej aplikacji (nie ma jej w bazie)
            privacy_light = "GRAY" # Lub GREEN
            privacy_desc = "Aplikacja nieznana - brak kategorii w bazie."

        # --- LOGIKA CVE (SECURITY ENGINE) ---
        # (Tutaj na razie prosto: sprawdzamy czy mamy CVE w bazie dla tej wersji)
        # W przyszłości: Join z tabelą version_vulnerabilities
        sec_light = "GREEN"
        sec_desc = "Brak znanych CVE."
        
        # --- BUDOWANIE WYNIKU ---
        result = AppScanResult(
            package_name=app_data.package_name,
            security=SecurityStatus(
                status_light=sec_light,
                description=sec_desc,
                cve_count=0,
                max_cvss=0.0
            ),
            privacy=PrivacyStatus(
                status_light=privacy_light,
                description=privacy_desc,
                violation_count=len(violations),
                risky_permissions=violations
            )
        )
        results.append(result)

    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        results=results
    )


@app.get("/")
def read_root():
    return {"status": "System działa poprawnie", "docs": "/docs", "admin": "/admin"}