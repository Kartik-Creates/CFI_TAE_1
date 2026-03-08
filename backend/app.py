from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime
import uvicorn

from database import get_db, init_db
from models import SystemAssessment, RiskResult, Alert
from data_collector import DataCollector
from risk_engine import RiskEngine
from ml_model import MLThreatDetector
from alert_system import AlertSystem
import schemas

app = FastAPI(title="Cyber Risk Assessment API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # safer than "*"
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
data_collector = DataCollector()
risk_engine = RiskEngine()
ml_detector = MLThreatDetector()
alert_system = AlertSystem()


# Startup event
@app.on_event("startup")
async def startup_event():
    init_db()
    ml_detector.load_models()


@app.get("/")
async def root():
    return {"message": "Cyber Risk Assessment API", "version": "1.0.0"}


# ===============================
# SECURITY SCAN ENDPOINT
# ===============================

@app.api_route("/api/scan", methods=["GET", "POST"])
async def perform_scan(
    background_tasks: BackgroundTasks,
    system_id: str = "host-01",
    db: Session = Depends(get_db)
):
    try:

        # Collect system data
        assessment_data = data_collector.perform_full_assessment(system_id)

        # Calculate risk score
        risk_result = risk_engine.calculate_overall_risk(assessment_data)

        # ML prediction
        ml_prediction = ml_detector.predict_threat(assessment_data)

        # Recommendations
        recommendations = risk_engine.get_recommendations(
            assessment_data,
            risk_result["components"]
        )

        # Alerts
        alerts = alert_system.check_and_generate_alerts(assessment_data, risk_result)

        # ===============================
        # FILTER DATA FOR DATABASE MODEL
        # ===============================

        allowed_fields = {
            "system_id",
            "failed_logins",
            "open_ports",
            "critical_ports",
            "patches_missing",
            "malware_indicators",
            "suspicious_ips"
        }

        filtered_data = {
            k: v for k, v in assessment_data.items()
            if k in allowed_fields
        }

        db_assessment = SystemAssessment(**filtered_data)

        db.add(db_assessment)
        db.flush()

        db_risk_result = RiskResult(
            assessment_id=db_assessment.id,
            risk_score=risk_result["risk_score"],
            threat_level=risk_result["threat_level"],
            ml_prediction=ml_prediction["threat_probability"],
            attack_probability=ml_prediction["threat_probability"]
        )

        db.add(db_risk_result)

        for alert in alerts:
            db_alert = Alert(**alert)
            db.add(db_alert)

        db.commit()

        response = {
            "system_id": system_id,
            "assessment_date": datetime.utcnow(),
            "risk_score": risk_result["risk_score"],
            "threat_level": risk_result["threat_level"],
            "ml_prediction": ml_prediction,
            "detected_issues": [
                {
                    "category": key.replace("_", " ").title(),
                    "value": value
                }
                for key, value in risk_result["components"].items()
                if value > 30
            ],
            "recommendations": recommendations,
            "alerts": alerts,
            "raw_data": assessment_data
        }

        return response

    except Exception as e:
        print("SCAN ERROR:", e)
        raise HTTPException(status_code=500, detail=str(e))


# ===============================
# RISK SCORE
# ===============================

@app.get("/api/risk-score/{system_id}")
async def get_risk_score(system_id: str, db: Session = Depends(get_db)):

    assessment = db.query(SystemAssessment).filter(
        SystemAssessment.system_id == system_id
    ).order_by(SystemAssessment.assessment_date.desc()).first()

    if not assessment:
        raise HTTPException(status_code=404, detail="System not found")

    risk_result = db.query(RiskResult).filter(
        RiskResult.assessment_id == assessment.id
    ).first()

    return {
        "system_id": system_id,
        "risk_score": risk_result.risk_score if risk_result else None,
        "threat_level": risk_result.threat_level if risk_result else None,
        "assessment_date": assessment.assessment_date
    }


# ===============================
# HISTORY
# ===============================

@app.get("/api/history/{system_id}")
async def get_assessment_history(system_id: str, limit: int = 10, db: Session = Depends(get_db)):

    assessments = db.query(SystemAssessment).filter(
        SystemAssessment.system_id == system_id
    ).order_by(SystemAssessment.assessment_date.desc()).limit(limit).all()

    history = []

    for assessment in assessments:

        risk_result = db.query(RiskResult).filter(
            RiskResult.assessment_id == assessment.id
        ).first()

        history.append({
            "assessment_id": assessment.id,
            "date": assessment.assessment_date,
            "risk_score": risk_result.risk_score if risk_result else None,
            "threat_level": risk_result.threat_level if risk_result else None,
            "failed_logins": assessment.failed_logins,
            "open_ports": assessment.open_ports,
            "malware_indicators": assessment.malware_indicators
        })

    return history


# ===============================
# ALERT RESOLUTION
# ===============================

@app.post("/api/alerts/resolve/{alert_id}")
async def resolve_alert(alert_id: int, db: Session = Depends(get_db)):

    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_resolved = True
    db.commit()

    return {"message": "Alert resolved successfully"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)