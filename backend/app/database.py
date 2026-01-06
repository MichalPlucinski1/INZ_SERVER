import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker,Session,  declarative_base

# Pobieramy URL z .env (który Docker podstawi automatycznie)
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()




def init_db_data(db: Session):
    # IMPORT LOKALNY - Musimy zaimportować też app_category_association!
    from .models import Category, PermissionRule, Severity, Application, app_category_association

    if db.query(Category).first():
        return 

    print("--- INICJALIZACJA BAZY DANYCH (SEED MULTI-CATEGORY) ---")

    cat_social = Category(name="SOCIAL", description="Social Media")
    cat_utility = Category(name="UTILITY", description="Narzędzia")
    cat_game = Category(name="GAME", description="Gry")
    
    db.add_all([cat_social, cat_utility, cat_game])
    db.commit()

    # Przykładowe Reguły
    rule_1 = PermissionRule(
        category_id=cat_utility.id,
        permission_name="android.permission.READ_CONTACTS",
        severity=Severity.CRITICAL,
        risk_message="Narzędzie nie powinno czytać kontaktów!"
    )
    
    # Dodajemy regułę dla SOCIAL (żeby przetestować działanie)
    rule_social = PermissionRule(
        category_id=cat_social.id,
        permission_name="android.permission.ACCESS_FINE_LOCATION",
        severity=Severity.WARNING,
        risk_message="Social Media śledzi Twoją lokalizację."
    )

    db.add_all([rule_1, rule_social])
    db.commit()
    
    # Aplikacje z wieloma kategoriami
    
    # Facebook: Jest i SOCIAL i UTILITY (bo ma dużo narzędzi)
    app_fb = Application(package_name="com.facebook.katana", app_name="Facebook", vendor="Meta")
    app_fb.categories.append(cat_social) 
    app_fb.categories.append(cat_utility) # <-- Dwie kategorie!
    
    app_calc = Application(package_name="com.sec.android.app.popupcalculator", app_name="Kalkulator", vendor="Samsung")
    app_calc.categories.append(cat_utility)

    db.add(app_fb)
    db.add(app_calc)
    
    db.commit()
    print("--- BAZA ZAŁADOWANA ---")

    
# Funkcja pomocnicza do pobierania sesji w endpointach (Dependency Injection)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


