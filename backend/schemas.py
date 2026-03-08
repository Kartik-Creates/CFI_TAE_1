from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict, Any

class AssessmentBase(BaseModel):
    system_id: str
    password_strength: int
    failed_logins: int
    open_ports: int
    critical_ports: int
    firewall_enabled: bool
    patches_installed: int
    patches_missing: int
    suspicious_ips: int
    traffic_anomaly_score: float
    malware_indicators: int
    antivirus_enabled: bool
    encryption_enabled: bool

class AssessmentCreate(AssessmentBase):
    pass

class AssessmentResponse(AssessmentBase):
    id: int
    user_id: Optional[int]
    assessment_date: datetime
    risk_score: float
    threat_level: str
    ml_prediction: Dict[str, Any]
    recommendations: List[Dict[str, str]]
    alerts: List[Dict[str, Any]]
    raw_data: Dict[str, Any]
   
    class Config:
        from_attributes = True

class RiskResultBase(BaseModel):
    risk_score: float
    threat_level: str
    ml_prediction: Optional[float]
    attack_probability: Optional[float]

class RiskResultCreate(RiskResultBase):
    assessment_id: int

class RiskResultResponse(RiskResultBase):
    id: int
    assessment_id: int
    timestamp: datetime
   
    class Config:
        from_attributes = True

class AlertBase(BaseModel):
    system_id: str
    alert_type: str
    severity: str
    description: str
    is_resolved: bool = False

class AlertCreate(AlertBase):
    pass

class AlertResponse(AlertBase):
    id: int
    timestamp: datetime
   
    class Config:
        from_attributes = True
