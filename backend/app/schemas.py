# app/schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class RegisterRequest(BaseModel):
    uuid: str = Field(..., description="Unikalny identyfikator wygenerowany przez klienta (UUID)")

class Token(BaseModel):
    access_token: str
    token_type: str


# --- Modele WYJŚCIOWE (To co zwracamy do Androida) ---
class AppAnalysisResult(BaseModel):
    package_name: str
    status: str
    security_light: int
    privacy_light: int
    summary: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class AnalysisResponse(BaseModel):
    results: List[AppAnalysisResult]

# --- Modele WEJŚCIOWE (To co przysyła Android) ---

class AppPayload(BaseModel):
    # Identyfikacja
    app_name: str
    package_name: str
    version_code: int
    version_name: str
    vendor: Optional[str] = None  # Np. "Android", "Microsoft Corporation..."
    
    # Bezpieczeństwo i Sklep
    is_from_store: bool
    installer_package: Optional[str] = None # Np. "com.android.vending" (Google Play)
    is_debuggable: bool
    signing_cert_hashes: List[str] = []
    
    # Nowe pola techniczne (bardzo ważne dla AI!)
    target_sdk: Optional[int] = None
    min_sdk: Optional[int] = None
    first_install_time: Optional[int] = None
    last_update_time: Optional[int] = None
    
    # Flagi zagrożeń
    has_exported_components: bool = False
    is_fingerprinting_suspected: bool = False # <--- Krytyczna flaga dla AI
    
    # Listy
    permissions: List[str] = []
    libraries: List[str] = []

# Główny Wrapper, bo JSON zaczyna się od {"apps": [...]}
class AnalysisRequest(BaseModel):
    apps: List[AppPayload]