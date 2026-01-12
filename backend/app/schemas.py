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

# --- WYJŚCIE (Updated) ---

class AiReportDetails(BaseModel):
    verdict_details: str
    risk_factors: List[str]
    positive_factors: List[str]
    permissions_analysis: Dict[str, Any]
    # trackers: List[str]
    # Opcjonalnie możemy tu powtórzyć score dla wygody UI
    security_score: int 
    privacy_score: int

class AndroidUiResult(BaseModel):
    package_name: str
    app_name: str
    version_code: int
    status: str
    
    # GŁÓWNY WERDYKT AI (1=Safe, 2=Warn, 3=Crit)
    security_light: Optional[int] = None
    privacy_light: Optional[int] = None
    
    # Flagi techniczne (wspomagające)
    is_up_to_date: Optional[bool] = None
    is_in_store: Optional[bool] = None
    downloaded_from_store: Optional[bool] = None
    is_cert_suspicious: Optional[str] = None
    vendor_status: Optional[str] = None
    target_sdk_secure: Optional[bool] = None
    debug_flag_off: Optional[bool] = None
    has_exported_components: Optional[bool] = None
    is_fingerprinting_suspected: Optional[bool] = None
    privacy_policy_exists: Optional[bool] = None
    
    short_summary: Optional[str] = None
    permissions: List[str] = [] 
    
    full_report: Optional[AiReportDetails] = None 

class AnalysisResponse(BaseModel):
    results: List[AndroidUiResult]