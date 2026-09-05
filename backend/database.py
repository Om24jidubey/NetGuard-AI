import os
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import declarative_base, sessionmaker

# 1. Configuration
# Check if DATABASE_URL is set (e.g., from Neon/Supabase), otherwise fallback to local SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./netguard.db")
DB_NAME = "netguard.db" # Kept for backwards compatibility

engine = create_engine(
    DATABASE_URL, 
    # check_same_thread=False is needed for SQLite to avoid concurrency errors in FastAPI
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 2. Schema Definition
class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True) # Storing as formatted string to match old schema exactly
    attack_type = Column(String)
    severity = Column(String)
    score = Column(Float)
    source_ip = Column(String)

def get_ist_now():
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")

def init_db():
    Base.metadata.create_all(bind=engine)

GLOBAL_TOTAL_THREATS = 0
GLOBAL_ATTACK_COUNTS = {}

def save_alert(attack_type, severity, score, source_ip):
    global GLOBAL_TOTAL_THREATS, GLOBAL_ATTACK_COUNTS
    GLOBAL_TOTAL_THREATS += 1
    GLOBAL_ATTACK_COUNTS[attack_type] = GLOBAL_ATTACK_COUNTS.get(attack_type, 0) + 1

    db = SessionLocal()
    try:
        new_alert = Alert(
            timestamp=get_ist_now(),
            attack_type=attack_type,
            severity=severity,
            score=score,
            source_ip=source_ip
        )
        db.add(new_alert)
        db.commit()
        
        # Enforce exactly 30 rows maximum
        count = db.query(Alert).count()
        if count > 30:
            excess = count - 30
            oldest_alerts = db.query(Alert).order_by(Alert.id.asc()).limit(excess).all()
            for old_alert in oldest_alerts:
                db.delete(old_alert)
            db.commit()
    except Exception as e:
        print(f"Error saving alert: {e}")
        db.rollback()
    finally:
        db.close()

def get_alert_history():
    db = SessionLocal()
    try:
        rows = db.query(Alert).order_by(Alert.id.desc()).limit(30).all()
        # Convert objects to dicts to match previous API
        return [
            {
                "id": row.id,
                "timestamp": row.timestamp,
                "attack_type": row.attack_type,
                "severity": row.severity,
                "score": row.score,
                "source_ip": row.source_ip
            }
            for row in rows
        ]
    finally:
        db.close()

def clear_all_alerts():
    db = SessionLocal()
    try:
        db.query(Alert).delete()
        db.commit()
    except Exception as e:
        print(f"Error clearing alerts: {e}")
        db.rollback()
    finally:
        db.close()
