import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/cyber_risk_db")
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    
    # Risk thresholds
    LOW_RISK_THRESHOLD = 30
    MEDIUM_RISK_THRESHOLD = 60
    HIGH_RISK_THRESHOLD = 100
    
    # Alert thresholds
    ALERT_THRESHOLD = 70
    
    # ML Model path
    ML_MODEL_PATH = "models/threat_model.pkl"