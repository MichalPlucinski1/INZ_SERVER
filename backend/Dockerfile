# Używamy lekkiego obrazu Pythona
FROM python:3.11-slim

# Ustawiamy katalog roboczy
WORKDIR /app

# Instalujemy zależności systemowe (potrzebne dla sterownika Postgresa)
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Kopiujemy plik zależności i instalujemy biblioteki
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy resztę kodu (chociaż docker-compose i tak to nadpisuje wolumenem)
COPY . .

# Port, na którym nasłuchuje aplikacja
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]