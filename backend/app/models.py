from sqlalchemy import Column, Integer, String, ForeignKey, Table, Float, DateTime, Text, Enum, JSON, BigInteger
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from .database import Base

# --- ENUMS ---
class Severity(str, enum.Enum):
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

# Aplikacja <-> Kategorie
app_category_association = Table(
    'app_category_association',
    Base.metadata,
    Column('application_pkg', String, ForeignKey('applications.package_name')),
    Column('category_id', Integer, ForeignKey('categories.id'))
)

# Wersja <-> CVE
version_cve_association = Table(
    'version_cve_association',
    Base.metadata,
    Column('app_version_id', Integer, ForeignKey('app_versions.id')),
    Column('cve_id', String, ForeignKey('cve_definitions.cve_id'))
)

# --- MODELE ---

class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True) 
    description = Column(String, nullable=True)
    
    # Relacje
    applications = relationship("Application", back_populates="category")
    rules = relationship("PermissionRule", back_populates="category")

class Application(Base):
    __tablename__ = "applications"
    package_name = Column(String, primary_key=True, index=True)
    app_name = Column(String)
    vendor = Column(String, nullable=True)
    
    # Cache kategorii (wypełniane przez AI lub ręcznie)
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    category = relationship("Category", back_populates="applications")

    # Historia wersji
    versions = relationship("AppVersion", back_populates="application")

class AppVersion(Base):
    __tablename__ = "app_versions"
    
    id = Column(Integer, primary_key=True, index=True)
    package_name = Column(String, ForeignKey("applications.package_name"))
    
    # Używamy BigInteger, bo Androidowy version_code może być ogromny
    version_code = Column(BigInteger) 
    version_name = Column(String, nullable=True)
    
    # Zapisujemy uprawnienia jako JSON - to jest nasza "fotografia" tej wersji
    permissions_snapshot = Column(JSON) 
    
    analyzed_at = Column(DateTime(timezone=True), server_default=func.now())

    application = relationship("Application", back_populates="versions")
    vulnerabilities = relationship("CveDefinition", secondary=version_cve_association)

class CveDefinition(Base):
    __tablename__ = "cve_definitions"
    cve_id = Column(String, primary_key=True)
    cvss_score = Column(Float)
    description = Column(Text)

class PermissionRule(Base):
    __tablename__ = "permission_rules"
    id = Column(Integer, primary_key=True, index=True)
    category_id = Column(Integer, ForeignKey("categories.id"))
    permission_name = Column(String)
    severity = Column(Enum(Severity))
    risk_message = Column(String)
    
    category = relationship("Category", back_populates="rules")