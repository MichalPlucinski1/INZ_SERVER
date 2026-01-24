# app/admin.py
import os
from sqladmin import ModelView, Admin
from sqladmin.authentication import AuthenticationBackend
from starlette.requests import Request
from starlette.responses import RedirectResponse
import logging

# IMPORTY Z NOWEJ STRUKTURY (ETAP 1)
from .infrastructure.database.models import AppAnalysis, TrustedVendor, AnalysisTask

logger = logging.getLogger("api_logger")

# --- KONFIGURACJA AUTH ---
class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request) -> bool:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")

        correct_user = os.getenv("ADMIN_USERNAME", "admin")
        correct_pass = os.getenv("ADMIN_PASSWORD", "changeme")

        if username == correct_user and password == correct_pass:
            request.session.update({"token": "admin_logged_in"})
            return True
        return False

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        token = request.session.get("token")
        logger.debug(f"🕵️ DEBUG SESSION CONTENT: {request.session}")
        if not token:
            return False
        return True

authentication_backend = AdminAuth(secret_key=os.getenv("SECRET_KEY", "supersecret"))

# --- WIDOKI MODELI ---

class AppAnalysisAdmin(ModelView, model=AppAnalysis):
    column_list = [
        AppAnalysis.id, 
        AppAnalysis.package_name, 
        AppAnalysis.status, 
        AppAnalysis.security_light, 
        AppAnalysis.created_at
    ]
    column_searchable_list = [AppAnalysis.package_name]
    column_sortable_list = [AppAnalysis.created_at, AppAnalysis.security_light]
    icon = "fa-solid fa-shield-halved"
    name = "Analiza Aplikacji"
    name_plural = "Analizy Aplikacji"

# NOWY WIDOK: KOLEJKA ZADAŃ (ETAP 2 PREP)
class AnalysisTaskAdmin(ModelView, model=AnalysisTask):
    column_list = [
        AnalysisTask.id,
        AnalysisTask.analysis_id,
        AnalysisTask.status,
        AnalysisTask.retry_count,
        AnalysisTask.locked_at,
        AnalysisTask.created_at
    ]
    column_filters = [AnalysisTask.status]
    column_sortable_list = [AnalysisTask.created_at, AnalysisTask.retry_count]
    name = "Zadanie Analizy"
    name_plural = "Kolejka Zadań"
    icon = "fa-solid fa-list-check"

class TrustedVendorAdmin(ModelView, model=TrustedVendor):
    column_list = [TrustedVendor.vendor_name, TrustedVendor.trust_level]
    column_searchable_list = [TrustedVendor.vendor_name]
    icon = "fa-solid fa-certificate"
    name = "Zaufany Producent"
    name_plural = "Zaufani Producenci"