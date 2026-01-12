# app/models.py
import os
import json
import sys # Dodane do wyjścia z błędem
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, LargeBinary, TypeDecorator
from sqlalchemy.sql import func
from cryptography.fernet import Fernet
from .database import Base

# --- KLUCZ SZYFRUJĄCY (POPRAWIONE) ---
key = os.getenv("DB_ENCRYPTION_KEY")

if not key:
    # CRITICAL FIX: Zatrzymujemy aplikację, jeśli brak klucza.
    # Generowanie losowego klucza tutaj to "cichy zabójca" danych.
    print("❌ CRITICAL ERROR: Brak DB_ENCRYPTION_KEY w zmiennych środowiskowych!")
    print("   Aplikacja nie może wystartować, bo grozi to utratą dostępu do zaszyfrowanych danych.")
    sys.exit(1)

cipher_suite = Fernet(key)

# --- WŁASNY TYP DANYCH: SZYFROWANY JSON ---
class EncryptedJSON(TypeDecorator):
    """
    Typ, który w Pythonie jest słownikiem (dict),
    ale w bazie jest zaszyfrowanym ciągiem bajtów (LargeBinary).
    """
    impl = LargeBinary
    cache_ok = True

    def process_bind_param(self, value, dialect):
        # Python -> Baza (Szyfrowanie)
        if value is None:
            return None
        json_str = json.dumps(value)
        encrypted_data = cipher_suite.encrypt(json_str.encode('utf-8'))
        return encrypted_data

    def process_result_value(self, value, dialect):
        # Baza -> Python (Deszyfrowanie)
        if value is None:
            return None
        try:
            decrypted_data = cipher_suite.decrypt(value)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception:
            # W razie błędu klucza lub uszkodzenia danych
            return {}

# --- MODELE ---

class AppAnalysis(Base):
    __tablename__ = "app_analyses"

    id = Column(Integer, primary_key=True, index=True)
    
    # Dane jawne (potrzebne do wyszukiwania)
    package_name = Column(String, index=True)
    version_code = Column(Integer)
    signing_cert_hash = Column(String)
    status = Column(String, default="PENDING")
    
    app_name = Column(String, nullable=True)
    vendor_name = Column(String, nullable=True)
    
    # Oceny (jawne dla szybkości)
    security_light = Column(Integer, default=0)
    privacy_light = Column(Integer, default=0)
    
    # Flagi techniczne
    is_up_to_date = Column(Boolean, default=True)
    privacy_policy_exists = Column(Boolean, default=False)
    cert_status = Column(String, default="no_info")
    
    target_sdk = Column(Integer, nullable=True)
    is_debuggable = Column(Boolean, default=False)
    has_exported_components = Column(Boolean, default=False)
    is_fingerprinting_suspected = Column(Boolean, default=False)
    is_from_store = Column(Boolean, default=False)
    installer_package = Column(String, nullable=True)
    
    short_summary = Column(Text, nullable=True)
    
    # --- DANE SZYFROWANE (Najwięcej informacji wrażliwych) ---
    # Zmieniamy JSONB na nasz EncryptedJSON
    full_report = Column(EncryptedJSON, nullable=True) 
    
    # Permissions i libraries też można zaszyfrować, jeśli chcemy ukryć
    # co apka robi, ale zazwyczaj zostawia się je jawne.
    # Dla przykładu zostawiamy permissions jawne (JSONB nie zadziała z EncryptedJSON bez przeróbki na tekst)
    # Zróbmy prosty JSON -> Text (SQLAlchemy JSON zazwyczaj działa, ale EncryptedJSON bazuje na binarnym)
    
    # Użyjmy EncryptedJSON też dla list, bo to po prostu Python List -> JSON -> Encrypt
    permissions = Column(EncryptedJSON, default=[])
    libraries = Column(EncryptedJSON, default=[])

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class TrustedVendor(Base):
    __tablename__ = "trusted_vendors"
    id = Column(Integer, primary_key=True, index=True)
    vendor_name = Column(String, index=True, nullable=False)
    known_cert_hash = Column(String, unique=True, nullable=False)
    trust_level = Column(String, default="VERIFIED")
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())