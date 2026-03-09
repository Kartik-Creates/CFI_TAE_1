from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime
import uvicorn
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from database import get_db, init_db
from models import SystemAssessment, RiskResult, Alert, User
from data_collector import DataCollector
from risk_engine import RiskEngine
from ml_model import MLThreatDetector
from alert_system import AlertSystem
import schemas


app = FastAPI(title="Cyber Risk Assessment API", version="1.0.0")

# ===============================
# CORS CONFIGURATION
# ===============================

allowed_origins = os.getenv("ALLOWED_ORIGINS")

if allowed_origins:
    origins = allowed_origins.split(",")
else:
    origins = [
        "http://localhost:3000",
        "https://cyber-risk.vercel.app"
    ]

print(f"✅ Allowed CORS origins: {origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===============================
# INITIALIZE COMPONENTS
# ===============================

data_collector = DataCollector()
risk_engine = RiskEngine()
ml_detector = MLThreatDetector()
alert_system = AlertSystem()

# ===============================
# STARTUP EVENT
# ===============================

@app.on_event("startup")
async def startup_event():

    try:
        init_db()
        print("✅ Database initialized successfully!")
    except Exception as e:
        print(f"⚠️ Database initialization warning: {e}")

    try:
        ml_detector.load_models()
        print("✅ ML models loaded successfully!")
    except Exception as e:
        print(f"⚠️ ML model loading warning: {e}")


# ===============================
# ROOT ENDPOINT
# ===============================

@app.get("/")
async def root():
    return {
        "message": "Cyber Risk Assessment API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


# ===============================
# SCAN ENDPOINT
# ===============================

@app.api_route("/api/scan", methods=["GET", "POST"])
async def perform_scan(
    background_tasks: BackgroundTasks,
    system_id: str = "host-01",
    db: Session = Depends(get_db)
):

    try:

        print(f"🔍 Starting scan for system: {system_id}")

        assessment_data = data_collector.perform_full_assessment(system_id)

        risk_result = risk_engine.calculate_overall_risk(assessment_data)

        ml_prediction = ml_detector.predict_threat(assessment_data)

        recommendations = risk_engine.get_recommendations(
            assessment_data,
            risk_result["components"]
        )

        alerts = alert_system.check_and_generate_alerts(
            assessment_data,
            risk_result
        )

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

        db_assessment = SystemAssessment(
            **filtered_data,
            assessment_date=datetime.utcnow()
        )

        db.add(db_assessment)
        db.flush()

        db_risk_result = RiskResult(
            assessment_id=db_assessment.id,
            risk_score=risk_result["risk_score"],
            threat_level=risk_result["threat_level"],
            ml_prediction=ml_prediction.get("threat_probability", 0),
            attack_probability=ml_prediction.get("threat_probability", 0)
        )

        db.add(db_risk_result)

        for alert in alerts:
            db_alert = Alert(
                **alert,
                assessment_id=db_assessment.id,
                created_date=datetime.utcnow()
            )
            db.add(db_alert)

        db.commit()

        response = {
            "success": True,
            "system_id": system_id,
            "assessment_date": db_assessment.assessment_date.isoformat(),
            "assessment_id": db_assessment.id,
            "risk_score": risk_result["risk_score"],
            "threat_level": risk_result["threat_level"],
            "ml_prediction": ml_prediction,
            "recommendations": recommendations,
            "alerts": alerts,
            "raw_data": assessment_data
        }

        return response

    except Exception as e:

        print(f"❌ SCAN ERROR: {str(e)}")

        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)}"
        )


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
async def get_assessment_history(
    system_id: str,
    limit: int = 10,
    db: Session = Depends(get_db)
):

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
            "threat_level": risk_result.threat_level if risk_result else None
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


# ===============================
# ERROR HANDLER
# ===============================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail
        }
    )


# ===============================
# MAIN
# ===============================

if __name__ == "__main__":

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )
