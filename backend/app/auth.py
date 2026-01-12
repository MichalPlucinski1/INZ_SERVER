# app/auth.py
import os
import sys
import jwt
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials # <--- ZMIANA
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    print("❌ CRITICAL ERROR: Brak SECRET_KEY w .env! Nie można uruchomić bezpiecznego auth.")
    sys.exit(1)

ALGORITHM = os.getenv("ALGORITHM", "HS256")

# ZMIANA: Zamiast OAuth2PasswordBearer używamy HTTPBearer.
# To mówi Swaggerowi: "Oczekuję nagłówka Authorization: Bearer <token>"
# i wyświetla proste pole tekstowe do wklejenia tokena.
security = HTTPBearer()

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=365)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user_uuid(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    Dependency function.
    FastAPI (HTTPBearer) automatycznie wyciąga token z nagłówka.
    Obiekt credentials ma pole .credentials, w którym siedzi sam string tokena.
    """
    token = credentials.credentials # <--- Wyciągamy czysty token string
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_uuid: str = payload.get("sub")
        if user_uuid is None:
            raise credentials_exception
        return user_uuid
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise credentials_exception