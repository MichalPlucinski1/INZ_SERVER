# app/schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

# --- WEJŚCIE (Bez zmian) ---
class AppPayload(BaseModel):
    app_name: str
    package_name: str
    version_code: int
    version_name: str
    vendor: Optional[str] = None
    is_from_store: bool
    installer_package: Optional[str] = None
    is_debuggable: bool
    signing_cert_hashes: List[str] = []
    target_sdk: Optional[int] = None
    min_sdk: Optional[int] = None
    first_install_time: Optional[int] = None
    last_update_time: Optional[int] = None
    has_exported_components: bool = False
    is_fingerprinting_suspected: bool = False
    permissions: List[str] = []
    libraries: List[str] = []

class AnalysisRequest(BaseModel):
    apps: List[AppPayload]

class RegisterRequest(BaseModel):
    uuid: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- WYJŚCIE (Zmiany na Optional) ---

class AndroidUiResult(BaseModel):
    # Pola identyfikacyjne (Zawsze muszą być, żeby Android wiedział co odświeżyć)
    package_name: str
    app_name: str
    version_code: int
    status: str
    
    # --- Poniższe pola będą NULL jeśli status == PENDING ---
    
    # Światła
    security_light: Optional[int] = None
    privacy_light: Optional[int] = None
    
    # Flagi logiczne
    is_up_to_date: Optional[bool] = None
    is_in_store: Optional[bool] = None
    downloaded_from_store: Optional[bool] = None
    
    # Status certyfikatu
    is_cert_suspicious: Optional[str] = None
    
    # Flagi techniczne
    target_sdk_secure: Optional[bool] = None
    debug_flag_off: Optional[bool] = None
    has_exported_components: Optional[bool] = None
    is_fingerprinting_suspected: Optional[bool] = None
    privacy_policy_exists: Optional[bool] = None
    
    # Treści
    short_summary: Optional[str] = None
    permissions: List[str] = [] # Lista może być pusta
    full_report: Optional[Dict[str, Any]] = None

class AnalysisResponse(BaseModel):
    results: List[AndroidUiResult]