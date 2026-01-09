import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Pobieramy URL z .env (zdefiniowany w docker-compose)
# Domyślnie na localhost, ale w Dockerze nadpisze to zmienna
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://admin:secret@localhost:5432/app_db")

# Tworzenie silnika DB
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Fabryka sesji
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Klasa bazowa dla modeli
Base = declarative_base()

# Dependency (Zależność) dla FastAPI
# To pozwala bezpiecznie otwierać i zamykać sesję przy każdym zapytaniu
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()