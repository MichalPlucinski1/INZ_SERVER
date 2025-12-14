import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Pobieramy URL z .env (który Docker podstawi automatycznie)
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Funkcja pomocnicza do pobierania sesji w endpointach (Dependency Injection)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()