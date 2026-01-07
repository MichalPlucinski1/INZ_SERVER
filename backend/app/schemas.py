from pydantic import BaseModel
from typing import List, Optional

# --- MODELE WEJŚCIOWE (To wysyła Android) ---

class AppPayload(BaseModel):
    package_name: str
    app_name: str
    version_code: int
    version_name: str
    permissions: List[str]  # np. ["android.permission.CAMERA", ...]

class ScanRequest(BaseModel):
    device_id: Optional[str] = None # Opcjonalne ID urządzenia
    apps: List[AppPayload]          # Lista aplikacji do sprawdzenia

# --- MODELE WYJŚCIOWE (To zwraca Serwer) ---

class SecurityStatus(BaseModel):
    status_light: str    # "GREEN", "YELLOW", "RED"
    description: str     # np. "Brak znanych podatności"
    cve_count: int
    max_cvss: float

class PrivacyStatus(BaseModel):
    status_light: str    # "GREEN", "YELLOW", "RED"
    description: str     # np. "Wykryto 2 podejrzane uprawnienia"
    violation_count: int
    risky_permissions: List[str]

class AppScanResult(BaseModel):
    package_name: str
    security: SecurityStatus
    privacy: PrivacyStatus

class ScanResponse(BaseModel):
    scan_id: str
    results: List[AppScanResult]