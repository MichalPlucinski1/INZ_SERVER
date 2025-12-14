from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Table, Float, DateTime, Text, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from .database import Base

# --- ENUMY (Słowniki) ---
class Severity(str, enum.Enum):
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

# --- TABELE ŁĄCZĄCE (Many-to-Many) ---
# Tabela łącząca Aplikacje z Kategoriami (np. Instagram -> Social + Photo)
app_category_association = Table(
    'app_category_association',
    Base.metadata,
    Column('application_pkg', String, ForeignKey('applications.package_name')),
    Column('category_id', Integer, ForeignKey('categories.id'))
)

# --- MODELE (Tabele) ---

class Category(Base):
    __tablename__ = "categories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True) # np. SOCIAL, UTILITY
    description = Column(String, nullable=True)
    
    # Relacja zwrotna do aplikacji
    applications = relationship("Application", secondary=app_category_association, back_populates="categories")
    # Relacja do reguł (reguły są per kategoria)
    rules = relationship("PermissionRule", back_populates="category")

class Application(Base):
    __tablename__ = "applications"

    package_name = Column(String, primary_key=True, index=True) # np. com.facebook.katana
    app_name = Column(String)
    vendor = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relacja: Aplikacja ma wiele kategorii
    categories = relationship("Category", secondary=app_category_association, back_populates="applications")

class CveDefinition(Base):
    __tablename__ = "cve_definitions"

    cve_id = Column(String, primary_key=True) # np. CVE-2023-1234
    cvss_score = Column(Float) # 0.0 - 10.0
    description = Column(Text)
    published_date = Column(DateTime, nullable=True)

class PermissionRule(Base):
    __tablename__ = "permission_rules"

    id = Column(Integer, primary_key=True, index=True)
    category_id = Column(Integer, ForeignKey("categories.id"))
    permission_name = Column(String, index=True) # np. android.permission.CAMERA
    
    is_allowed = Column(Boolean, default=False)
    severity = Column(Enum(Severity), default=Severity.WARNING)
    risk_message = Column(String)

    category = relationship("Category", back_populates="rules")

    def __repr__(self):
        return f"<Rule {self.permission_name} for Category {self.category_id}>"