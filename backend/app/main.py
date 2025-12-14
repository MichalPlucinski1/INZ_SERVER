import uuid
from fastapi import FastAPI
from sqladmin import Admin, ModelView
from .database import engine, Base
from .models import Application, Category, CveDefinition, PermissionRule
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

@app.post("/api/scan", response_model=ScanResponse)
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

@app.get("/")
def read_root():
    return {"status": "System działa poprawnie", "docs": "/docs", "admin": "/admin"}