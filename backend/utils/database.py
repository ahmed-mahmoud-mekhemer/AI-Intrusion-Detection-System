# backend/utils/database.py
# ─────────────────────────────────────────────────────────────────────────────
# SQLAlchemy setup and ORM model for the alerts table.
# ─────────────────────────────────────────────────────────────────────────────
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from datetime import datetime
from backend.config import DATABASE_URL, DB_PATH

# Ensure the data directory exists
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class AlertORM(Base):
    """SQLAlchemy ORM model for the alerts table."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(String, index=True)
    label = Column(String, index=True)
    severity = Column(String, index=True)
    confidence = Column(Float, nullable=True)
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String)
    timestamp = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    source = Column(String, default="pcap")
    detection_type = Column(String, default="RULE")
    detail = Column(String, nullable=True)


def init_db():
    """Create all tables. Called at backend startup."""
    Base.metadata.create_all(bind=engine)
    # Zero-downtime migration: add detection_type column for existing databases
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN detection_type TEXT DEFAULT 'RULE'"))
            conn.commit()
        except Exception:
            pass  # column already exists
        try:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN detail TEXT"))
            conn.commit()
        except Exception:
            pass  # column already exists


def get_db():
    """Dependency: yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
