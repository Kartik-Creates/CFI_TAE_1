from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

# ✅ USE ENVIRONMENT VARIABLE FOR DATABASE URL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./cyber_risk.db"  # Fallback for local development
)

print(f"📦 Using database: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else 'SQLite'}")

# Create engine with appropriate settings
if "postgresql" in DATABASE_URL:
    # PostgreSQL settings
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,  # Verify connections before using them
        pool_recycle=3600
    )
else:
    # SQLite settings for development
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database tables"""
    from models import Base
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created/verified successfully!")

def get_engine():
    """Get database engine"""
    return engine

def get_session():
    """Get new database session"""
    return SessionLocal()
