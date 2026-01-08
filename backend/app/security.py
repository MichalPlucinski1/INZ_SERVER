# app/security.py
import logging
from sqlalchemy.orm import Session
from . import models

logger = logging.getLogger(__name__)

def normalize_hash(cert_hash: str) -> str:
    """
    Zamienia format Androida (AA:BB:CC) na format bazy danych (AABBCC).
    """
    if not cert_hash:
        return ""
    # Usuwamy dwukropki, spacje i zamieniamy na wielkie litery
    return cert_hash.replace(":", "").replace(" ", "").upper()

def verify_app_signature(db: Session, package_name: str, incoming_hashes: list[str]) -> dict:
    """
    Sprawdza, czy hash z telefonu znajduje się na białej liście (TrustedVendor).
    """
    if not incoming_hashes:
        return {"status": "UNKNOWN", "vendor_name": None}
        
    # 1. Normalizacja (Android wysyła z dwukropkami, baza ma bez)
    cleaned_hashes = [normalize_hash(h) for h in incoming_hashes]

    # 2. Szukamy w bazie
    # Sprawdzamy, czy KTÓRYKOLWIEK z hashów przesłanych przez telefon jest zaufany
    trusted_entry = db.query(models.TrustedVendor).filter(
        models.TrustedVendor.known_cert_hash.in_(cleaned_hashes)
    ).first()

    if trusted_entry:
        return {
            "status": "TRUSTED",
            "vendor_name": trusted_entry.vendor_name
        }

    # Tutaj w przyszłości dodamy logikę "MISMATCH" (Spoofing detection)
    # np. jeśli package_name to "com.facebook.katana", ale hasha nie ma w bazie -> ALARM.
    
    return {"status": "UNKNOWN", "vendor_name": None}