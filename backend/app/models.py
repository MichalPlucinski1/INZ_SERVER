from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, Index
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.sql import func
from .database import Base

class TrustedVendor(Base):
    """
    Tabela 1: Whitelista zaufanych producentów.
    """
    __tablename__ = "trusted_vendors"

    id = Column(Integer, primary_key=True, index=True)
    vendor_name = Column(String, index=True, nullable=False)
    known_cert_hash = Column(String, unique=True, nullable=False) # SHA-256
    trust_level = Column(String, default="VERIFIED") 
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class AppAnalysis(Base):
    """
    Tabela 2: Wyniki analizy konkretnej wersji aplikacji.
    """
    __tablename__ = "app_analyses"

    id = Column(Integer, primary_key=True, index=True)

    # --- IDENTYFIKACJA WERSJI (Unikalna trójka) ---
    package_name = Column(String, nullable=False, index=True)
    version_code = Column(Integer, nullable=False)
    signing_cert_hash = Column(String, nullable=False, index=True)

    # --- DANE WEJŚCIOWE (Kontekst analizy) ---
    app_name = Column(String)
    version_name = Column(String)
    is_from_store = Column(Boolean)
    
    # Przechowujemy listy jako JSONB, bo łatwiej je zrzucić z payloadu Androida
    permissions = Column(JSONB) 
    libraries = Column(JSONB)

    # --- WYNIKI AI ---
    status = Column(String, default="PENDING") # PENDING, COMPLETED, ERROR, FAILED
    
    # Światła (1=Zielone, 2=Żółte, 3=Czerwone, 0=Brak danych)
    security_light = Column(Integer, default=0)
    privacy_light = Column(Integer, default=0)
    
    # Opisy
    short_summary = Column(Text)
    full_report = Column(JSONB) # Szczegóły dla kontrolek

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Indeks unikalny: nie chcemy analizować tej samej wersji dwa razy
    __table_args__ = (
        Index('uq_app_analysis', 'package_name', 'version_code', 'signing_cert_hash', unique=True),
    )