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
    is_from_store: bool = None
    installer_package: Optional[str] = None
    is_debuggable: bool = None
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
class PermissionsAnalysisData(BaseModel):
    dangerous_count: int
    summary: str # Krótkie podsumowanie niepokojących uprawnień w relacji do opisu

class AiFlatResponse(BaseModel):
    """
    Model używany bezpośrednio przez GeminiClient do wymuszenia 
    formatu JSON opisanego w Twoim prompcie.
    """
    security_score: int       # 1, 2 lub 3
    privacy_score: int        # 1, 2 lub 3
    short_summary: str        # Jedno zdanie po polsku
    verdict_details: str      # Techniczne uzasadnienie werdyktu
    risk_factors: List[str]   # Lista konkretnych zagrożeń
    positive_factors: List[str] # Lista zalet
    trackers: List[str]       # Lista wykrytych trackerów
    permissions_analysis: PermissionsAnalysisData

# --- WYJŚCIE (Dane przesyłane do UI aplikacji) ---

class AiReportDetails(AiFlatResponse):
    """
    Rozszerzony raport dla UI. Dziedziczy pola z AiFlatResponse, 
    co zapewnia pełną spójność z wynikiem bota.
    """
    pass

class AndroidUiResult(BaseModel):
    package_name: str
    app_name: str
    version_code: int
    status: str # PENDING, PROCESSING, COMPLETED, FAILED
    
    # GŁÓWNE OCENY (1=Safe, 2=Warn, 3=Crit)
    security_light: Optional[int] = None
    privacy_light: Optional[int] = None
    
    # Flagi techniczne (Interpretowane dla UI)
    is_up_to_date: Optional[bool] = None
    is_in_store: Optional[bool] = None
    downloaded_from_store: Optional[bool] = None
    vendor_status: Optional[str] = None # verified, suspected, no_negative_data
    target_sdk_secure: Optional[bool] = None
    debug_flag_off: Optional[bool] = None
    has_exported_components: Optional[bool] = None
    is_fingerprinting_suspected: Optional[bool] = None
    privacy_policy_exists: Optional[bool] = None
    
    short_summary: Optional[str] = None
    permissions: List[str] = [] 
    
    # Szczegółowy raport AI (pojawia się tylko gdy status == COMPLETED)
    full_report: Optional[AiReportDetails] = None 

class AnalysisResponse(BaseModel):
    results: List[AndroidUiResult]