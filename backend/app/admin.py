from sqladmin import ModelView
# BYŁO (BŁĄD): from .database import models
# JEST (POPRAWNIE): importujemy moduł models.py, który leży w tym samym katalogu
from . import models 

# Widok dla Tabeli Analiz
class AppAnalysisAdmin(ModelView, model=models.AppAnalysis):
    column_list = [
        models.AppAnalysis.id,
        models.AppAnalysis.package_name,
        models.AppAnalysis.version_code,
        models.AppAnalysis.status,
        models.AppAnalysis.security_light,
        models.AppAnalysis.created_at
    ]
    search_columns = [models.AppAnalysis.package_name]
    icon = "fa-solid fa-shield-halved" 

# Widok dla Zaufanych Dostawców
class TrustedVendorAdmin(ModelView, model=models.TrustedVendor):
    column_list = [
        models.TrustedVendor.vendor_name,
        models.TrustedVendor.trust_level,
        models.TrustedVendor.known_cert_hash
    ]
    search_columns = [models.TrustedVendor.vendor_name]
    icon = "fa-solid fa-check-circle"