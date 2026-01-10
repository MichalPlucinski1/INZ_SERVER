# app/models.py
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from .database import Base

class AppAnalysis(Base):
    __tablename__ = "app_analyses"

    id = Column(Integer, primary_key=True, index=True)
    
    # Identyfikacja
    package_name = Column(String, index=True)
    version_code = Column(Integer)
    signing_cert_hash = Column(String) # Czysty hash
    
    # Dane UI (Nowe kolumny)
    app_name = Column(String, nullable=True)
    vendor_name = Column(String, nullable=True) # Zidentyfikowany producent
    
    # Status analizy
    status = Column(String, default="PENDING")
    
    # Wyniki (Światła)
    security_light = Column(Integer, default=0)
    privacy_light = Column(Integer, default=0)
    
    # Flagi techniczne (Nowe kolumny - cache'ujemy to co wysłał telefon)
    target_sdk = Column(Integer, nullable=True)
    is_debuggable = Column(Boolean, default=False)
    has_exported_components = Column(Boolean, default=False)
    is_fingerprinting_suspected = Column(Boolean, default=False)
    is_from_store = Column(Boolean, default=False)
    installer_package = Column(String, nullable=True)
    
    # Wyniki Scrapera i Security (Obliczone)
    is_up_to_date = Column(Boolean, default=True) # Czy wersja zgadza się ze sklepem
    privacy_policy_exists = Column(Boolean, default=False)
    cert_status = Column(String, default="no_info") # trusted, suspicious, no_info
    
    # Raporty
    short_summary = Column(Text, nullable=True)
    full_report = Column(JSONB, nullable=True) # Tutaj trzymamy szczegóły dla ekranu "Details"
    
    # Listy (JSON)
    permissions = Column(JSONB, default=[])
    libraries = Column(JSONB, default=[])

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

# TrustedVendor bez zmian...
class TrustedVendor(Base):
    __tablename__ = "trusted_vendors"
    id = Column(Integer, primary_key=True, index=True)
    vendor_name = Column(String, index=True, nullable=False)
    known_cert_hash = Column(String, unique=True, nullable=False)
    trust_level = Column(String, default="VERIFIED")
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())