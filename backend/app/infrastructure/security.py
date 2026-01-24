# app/security.py
import logging
from sqlalchemy.orm import Session
from app.infrastructure.database import models

logger = logging.getLogger(__name__)

def normalize_hash(cert_hash: str) -> str:
    if not cert_hash:
        return ""
    return cert_hash.strip().replace(":", "").replace(" ", "").upper()

def check_security_alerts(db: Session, package_name: str, claimed_vendor: str, incoming_hashes: list[str]) -> dict:
    alerts = []
    status = "NEUTRAL"
    
    # POPRAWKA LOGIKI: Tworzymy zbiór (set) wszystkich hashy przesłanych przez apkę
    incoming_hashes_clean = {normalize_hash(h) for h in incoming_hashes if h}

    if not incoming_hashes_clean:
        return {"status": "UNKNOWN", "alerts": ["Brak hasha certyfikatu"]}

    # --- SCENARIUSZ A: Weryfikacja Vendora ---
    trusted_vendor = None
    if claimed_vendor:
        trusted_vendor = db.query(models.TrustedVendor).filter(
            models.TrustedVendor.vendor_name == claimed_vendor
        ).first()

    if trusted_vendor:
        known_hash = normalize_hash(trusted_vendor.known_cert_hash)
        
        # Sprawdzamy, czy ZNANY hash znajduje się w liście hashy aplikacji
        if known_hash in incoming_hashes_clean:
            status = "TRUSTED"
            alerts.append(f"✅ ZWERYFIKOWANO: Aplikacja {package_name} podpisana przez {trusted_vendor.vendor_name}.")
        else:
            status = "DANGER"
            alerts.append(f"⛔ SPOOFING: Aplikacja podaje się za '{claimed_vendor}', ale żaden z jej podpisów nie pasuje do wzorca!")

    # --- SCENARIUSZ B: Spójność Historii ---
    # Bierzemy "reprezentatywny" hash (np. pierwszy posortowany alfabetycznie dla powtarzalności) do porównania historii
    current_primary_hash = sorted(list(incoming_hashes_clean))[0]
    
    last_analysis = db.query(models.AppAnalysis).filter(
        models.AppAnalysis.package_name == package_name
    ).order_by(models.AppAnalysis.created_at.desc()).first()

    if last_analysis:
        history_hash = normalize_hash(last_analysis.signing_cert_hash)
        # Jeśli poprzedni hash był inny i nie ma go w obecnych (rotacja kluczy jest możliwa, ale rzadka w ten sposób)
        if history_hash and history_hash not in incoming_hashes_clean:
             # Jeśli status to TRUSTED (zweryfikowany vendor), to zmiana klucza jest mniej groźna (mogła być rotacja po stronie firmy)
             # Jeśli status to NEUTRAL, zmiana jest podejrzana.
            msg = (f"⚠️ ZMIANA PODPISU: Pakiet {package_name} zmienił klucz! "
                   f"Poprzednio: {history_hash[:8]}...")
            
            if status != "DANGER" and status != "TRUSTED":
                status = "WARNING"
            
            alerts.append(msg)

    return {
        "status": status,
        "alerts": alerts
    }