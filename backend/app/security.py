# app/security.py
import logging
from sqlalchemy.orm import Session
from . import models

logger = logging.getLogger(__name__)

def normalize_hash(cert_hash: str) -> str:
    """
    Przygotowuje hash do porównania/zapisu.
    Android wysyła teraz czysty HEX (np. AABBCC), ale dla pewności
    usuwamy białe znaki i wymuszamy wielkie litery.
    """
    if not cert_hash:
        return ""
    # Usuwamy ewentualne śmieci, gdyby jednak coś wpadło
    return cert_hash.strip().replace(":", "").replace(" ", "").upper()

def check_security_alerts(db: Session, package_name: str, claimed_vendor: str, incoming_hashes: list[str]) -> dict:
    """
    Weryfikuje podpis i historię.
    """
    alerts = []
    status = "NEUTRAL"
    
    # 1. Pobieramy i czyścimy hash (teraz zakładamy, że Android wysyła czysty, ale normalizujemy)
    current_hash = normalize_hash(incoming_hashes[0]) if incoming_hashes else None

    if not current_hash:
        return {"status": "UNKNOWN", "alerts": ["Brak hasha certyfikatu"]}

    # --- SCENARIUSZ A: Weryfikacja Vendora (TrustedVendor) ---
    trusted_vendor = None
    if claimed_vendor:
        # Szukamy vendora po nazwie
        trusted_vendor = db.query(models.TrustedVendor).filter(
            models.TrustedVendor.vendor_name == claimed_vendor
        ).first()

    if trusted_vendor:
        # Porównujemy znormalizowany hash z bazy z tym z Androida
        # (W bazie też trzymamy już tylko czyste hashe)
        if normalize_hash(trusted_vendor.known_cert_hash) == current_hash:
            status = "TRUSTED"
            alerts.append(f"✅ ZWERYFIKOWANO: Aplikacja {package_name} podpisana przez {trusted_vendor.vendor_name}.")
        else:
            status = "DANGER"
            alerts.append(f"⛔ SPOOFING: Aplikacja podaje się za '{claimed_vendor}', ale podpis jest NIEPOPRAWNY!")

    # --- SCENARIUSZ B: Spójność Historii (Consistency Check) ---
    # Szukamy ostatniej analizy dla tego pakietu.
    last_analysis = db.query(models.AppAnalysis).filter(
        models.AppAnalysis.package_name == package_name
    ).order_by(models.AppAnalysis.created_at.desc()).first()

    if last_analysis:
        # Pobieramy stary hash z bazy i upewniamy się, że jest znormalizowany (na wypadek starych danych)
        history_hash = normalize_hash(last_analysis.signing_cert_hash)
        
        if history_hash and history_hash != current_hash:
            msg = (f"⚠️ ZMIANA PODPISU: Pakiet {package_name} zmienił klucz! "
                   f"Poprzednio: {history_hash[:8]}..., Teraz: {current_hash[:8]}...")
            
            if status != "DANGER":
                status = "WARNING"
            
            alerts.append(msg)

    return {
        "status": status,
        "alerts": alerts
    }