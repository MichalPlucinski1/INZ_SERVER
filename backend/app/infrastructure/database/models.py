import os
import json
import sys
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, LargeBinary, TypeDecorator, ForeignKey
from sqlalchemy.sql import func
from cryptography.fernet import Fernet
from .database import Base

# --- LOGIKA SZYFROWANIA (Zachowana z Twojego modelu) ---
key = os.getenv("DB_ENCRYPTION_KEY")
if not key:
    print("❌ CRITICAL ERROR: Brak DB_ENCRYPTION_KEY!")
    sys.exit(1)
cipher_suite = Fernet(key)

class EncryptedJSON(TypeDecorator):
    impl = LargeBinary
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None: return None
        json_str = json.dumps(value)
        return cipher_suite.encrypt(json_str.encode('utf-8'))

    def process_result_value(self, value, dialect):
        if value is None: return None
        try:
            decrypted_data = cipher_suite.decrypt(value)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception: return {}

# --- MODELE ---

class AppAnalysis(Base):
    """Przechowuje WYNIK analizy (Magazyn Danych)"""
    __tablename__ = "app_analyses"

    id = Column(Integer, primary_key=True, index=True)
    package_name = Column(String, index=True)
    version_code = Column(Integer)
    signing_cert_hash = Column(String)
    status = Column(String, default="PENDING")
    
    app_name = Column(String, nullable=True)
    vendor_name = Column(String, nullable=True)
    security_light = Column(Integer, default=0)
    privacy_light = Column(Integer, default=0)
    
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
    
    full_report = Column(EncryptedJSON, nullable=True) 
    permissions = Column(EncryptedJSON, default=[])
    libraries = Column(EncryptedJSON, default=[])

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class AnalysisTask(Base):
    """Zarządza KOLEJKĄ zadań (Moduł Zarządzania Zadaniami)"""
    __tablename__ = "analysis_tasks"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("app_analyses.id"), nullable=False)
    
    status = Column(String, default="PENDING") # PENDING, PROCESSING, COMPLETED, FAILED
    retry_count = Column(Integer, default=0)
    priority = Column(Integer, default=0)      # Im wyższy, tym szybciej (FIFO domyślnie)
    
    locked_at = Column(DateTime(timezone=True), nullable=True) # Zapobiega dublowaniu zadań
    last_error = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class TrustedVendor(Base):
    __tablename__ = "trusted_vendors"
    id = Column(Integer, primary_key=True, index=True)
    vendor_name = Column(String, index=True, nullable=False)
    known_cert_hash = Column(String, unique=True, nullable=False)
    trust_level = Column(String, default="VERIFIED")
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())