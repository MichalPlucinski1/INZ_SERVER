import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker,Session,  declarative_base

# Pobieramy URL z .env (który Docker podstawi automatycznie)
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()




def init_db_data(db: Session):
    """
    Funkcja startowa: Dodaje przykładowe reguły i kategorie,
    żeby system nie był pusty na prezentacji.
    """

    from .models import Category, PermissionRule, Severity, Application, app_category_association


    # 1. Sprawdzamy, czy mamy już kategorie
    if db.query(Category).first():
        return # Baza już pełna, nie robimy nic

    print("--- INICJALIZACJA BAZY DANYCH (SEED) ---")

    # 2. Tworzymy Kategorie
    cat_social = Category(name="SOCIAL", description="Social Media & Messengers")
    cat_utility = Category(name="UTILITY", description="Narzędzia (Latarki, Kalkulatory)")
    cat_game = Category(name="GAME", description="Gry")
    
    db.add_all([cat_social, cat_utility, cat_game])
    db.commit()

    # 3. Tworzymy Reguły (To jest Twój silnik decyzyjny!)
    
    # Reguła A: Narzędzia (np. Latarka) nie powinny czytać kontaktów -> CRITICAL
    rule_1 = PermissionRule(
        category_id=cat_utility.id,
        permission_name="android.permission.READ_CONTACTS",
        is_allowed=False,
        severity=Severity.CRITICAL,
        risk_message="Aplikacja narzędziowa nie powinna czytać Twoich kontaktów!"
    )

    # Reguła B: Narzędzia nie powinny używać Internetu (jeśli są offline) -> WARNING
    rule_2 = PermissionRule(
        category_id=cat_utility.id,
        permission_name="android.permission.INTERNET",
        is_allowed=False,
        severity=Severity.WARNING,
        risk_message="Podejrzany dostęp do Internetu w prostej aplikacji."
    )

    # Reguła C: Gry nie powinny mieć dostępu do SMS -> CRITICAL
    rule_3 = PermissionRule(
        category_id=cat_game.id,
        permission_name="android.permission.SEND_SMS",
        is_allowed=False,
        severity=Severity.CRITICAL,
        risk_message="Gra próbuje wysyłać SMSy (możliwe SMS Premium)."
    )

    db.add_all([rule_1, rule_2, rule_3])
    db.commit()
    
    # 4. Dodajmy "znane" aplikacje do bazy, żeby system wiedział czym one są
    # (W przyszłości zrobi to AI, teraz robimy to ręcznie dla demo)
    
    # Facebook -> SOCIAL
    app_fb = Application(package_name="com.facebook.katana", app_name="Facebook", vendor="Meta")
    app_fb.categories.append(cat_social)
    
    # Przykładowy Kalkulator -> UTILITY
    # (Tutaj wpisz package_name jakiegoś kalkulatora, który masz na telefonie, np. systemowy)
    app_calc = Application(package_name="com.sec.android.app.popupcalculator", app_name="Kalkulator Samsung", vendor="Samsung")
    app_calc.categories.append(cat_utility)

    # Przykład Twojej złośliwej apki (jeśli taką napiszesz)
    app_malware = Application(package_name="com.example.latarka", app_name="Zła Latarka", vendor="Hacker")
    app_malware.categories.append(cat_utility)

    db.add(app_fb)
    db.add(app_calc)
    db.add(app_malware)
    
    db.commit()
    print("--- BAZA ZAŁADOWANA PRZYKŁADAMI ---")

# Funkcja pomocnicza do pobierania sesji w endpointach (Dependency Injection)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


