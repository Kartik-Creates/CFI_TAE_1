from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    password_hash = Column(String(200))
    role = Column(String(20), default="analyst")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    assessments = relationship("SystemAssessment", back_populates="user")

class SystemAssessment(Base):
    __tablename__ = "system_assessments"
    
    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(String(50), index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    assessment_date = Column(DateTime, default=datetime.utcnow)
    
    # Security parameters
    password_strength = Column(Integer)  # 0-100
    failed_logins = Column(Integer)
    open_ports = Column(Integer)
    critical_ports = Column(Integer)
    firewall_enabled = Column(Boolean)
    patches_installed = Column(Integer)
    patches_missing = Column(Integer)
    suspicious_ips = Column(Integer)
    traffic_anomaly_score = Column(Float)  # 0-1
    malware_indicators = Column(Integer)
    antivirus_enabled = Column(Boolean)
    encryption_enabled = Column(Boolean)
    
    user = relationship("User", back_populates="assessments")
    risk_result = relationship("RiskResult", back_populates="assessment", uselist=False)

class RiskResult(Base):
    __tablename__ = "risk_results"
    
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("system_assessments.id"))
    risk_score = Column(Float)
    threat_level = Column(String(20))
    ml_prediction = Column(Float, nullable=True)
    attack_probability = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    assessment = relationship("SystemAssessment", back_populates="risk_result")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(String(50), index=True)
    alert_type = Column(String(50))
    severity = Column(String(20))
    description = Column(Text)
    is_resolved = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)