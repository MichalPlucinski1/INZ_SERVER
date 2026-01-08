from pydantic import BaseModel, Field
from typing import List, Optional

# --- Modele Wejściowe (Odbierane z telefonu) ---

class AppPayload(BaseModel):
    """
    Odwzorowanie struktury JSON z dokumentacji Androida.
    """
    app_name: str
    package_name: str
    version_name: str
    version_code: int
    target_sdk: int
    min_sdk: int
    installer_package: Optional[str] = None
    is_from_store: bool
    is_debuggable: bool
    has_exported_components: bool
    first_install_time: int
    last_update_time: int
    is_fingerprinting_suspected: bool
    signing_cert_hashes: List[str]
    permissions: List[str]
    libraries: List[str]

class AnalysisRequest(BaseModel):
    """
    Główny obiekt POST wysyłany przez aplikację.
    """
    device_id: str
    apps: List[AppPayload]

# --- Modele Wyjściowe (Wysyłane do telefonu) ---

class AppAnalysisResult(BaseModel):
    package_name: str
    status: str # PENDING, COMPLETED
    
    # Te pola są opcjonalne, bo przy statusie PENDING ich nie będzie
    security_light: Optional[int] = 0
    privacy_light: Optional[int] = 0
    summary: Optional[str] = None
    details: Optional[dict] = None # Pełen raport JSON

class AnalysisResponse(BaseModel):
    results: List[AppAnalysisResult]