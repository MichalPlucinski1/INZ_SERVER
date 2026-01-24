import asyncio
import logging
import datetime
from app.infrastructure.database.database import SessionLocal
from app.infrastructure.database import models
from .perform_analysis import run_analysis_flow

logger = logging.getLogger("task_worker")

async def process_pending_tasks():
    logger.info("✅ Worker kolejki zadań uruchomiony (Tryb: Sekwencyjny).")
    
    # Stały odstęp bezpieczeństwa (w sekundach)
    DELAY_BETWEEN_TASKS = 5.0 

    while True:
        db = SessionLocal()
        try:
            # 1. Pobieramy tylko 1 zadanie na raz (LIMIT 1)
            # System wybiera najstarsze (FIFO) zadanie PENDING/FAILED
            task = db.query(models.AnalysisTask).filter(
                models.AnalysisTask.status.in_(["PENDING", "FAILED"]),
                models.AnalysisTask.retry_count < 2,
                models.AnalysisTask.locked_at == None
            ).order_by(
                models.AnalysisTask.priority.desc(), 
                models.AnalysisTask.created_at.asc()
            ).first()

            if not task:
                await asyncio.sleep(5) 
                continue

            # 2. Blokada zadania w bazie danych przed rozpoczęciem pracy
            task.locked_at = datetime.datetime.utcnow()
            task.status = "PROCESSING"
            db.commit()

            logger.info(f"🚀 Rozpoczynam zadanie {task.id}. Kolejne nie ruszy przed upływem {DELAY_BETWEEN_TASKS}s.")

            try:
                # Wykonanie ciężkiej pracy (Scraper + AI)
                await run_analysis_flow(db, task.analysis_id)
                task.status = "COMPLETED"
                logger.info(f"✅ Zadanie {task.id} zakończone sukcesem.")
            except Exception as e:
                task.retry_count += 1
                task.last_error = str(e)
                # Jeśli to była 2 próba, oznaczamy jako trwały błąd
                task.status = "FAILED" if task.retry_count >= 2 else "PENDING"
                logger.error(f"❌ Błąd zadania {task.id} (Próba {task.retry_count}/2): {e}")
            
            # 3. Zdejmujemy blokadę i zapisujemy wynik
            task.locked_at = None
            db.commit()

            # --- KRYTYCZNA PRZERWA (THROTTLING) ---
            # To gwarantuje, że worker "odpocznie" przed pobraniem kolejnego rekordu
            logger.info(f"⏳ Chłodzenie systemu... {DELAY_BETWEEN_TASKS}s przerwy.")
            await asyncio.sleep(DELAY_BETWEEN_TASKS) 

        except Exception as e:
            logger.error(f"⚠️ Krytyczny błąd w pętli workera: {e}")
            await asyncio.sleep(10) # Dłuższa przerwa przy błędzie bazy danych
        finally:
            db.close()