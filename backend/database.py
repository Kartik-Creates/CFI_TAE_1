# backend/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Use SQLite for development (easier for Windows)
SQLALCHEMY_DATABASE_URL = "sqlite:///./cyber_risk.db"

# Create engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}  # Needed for SQLite
)

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base class
Base = declarative_base()

# Dependency to get DB session
def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database tables"""
    # Import models here to avoid circular imports
    from models import Base
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully!")

def get_engine():
    """Get database engine"""
    return engine

def get_session():
    """Get new database session"""
    return SessionLocal()