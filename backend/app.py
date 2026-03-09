from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
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
# CORS CONFIGURATION (IMPORTANT FOR PRODUCTION)
# ===============================

allowed_origins = os.getenv("ALLOWED_ORIGINS")

if allowed_origins:
    origins = allowed_origins.split(",")
else:
    origins = [
        "http://localhost:3000",
        "https://cyber-risk.vercel.app",
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
    """Initialize database and load ML models on startup"""
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
# HEALTH CHECK ENDPOINT
# ===============================

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "Cyber Risk Assessment API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/api/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected"
    }


# ===============================
# SECURITY SCAN ENDPOINT
# ===============================

@app.api_route("/api/scan", methods=["GET", "POST"])
async def perform_scan(
    background_tasks: BackgroundTasks,
    system_id: str = "host-01",
    db: Session = Depends(get_db)
):
    """
    Perform comprehensive security scan on a system
    
    Parameters:
    - system_id: Identifier for the system being scanned
    
    Returns:
    - Comprehensive risk assessment with recommendations and alerts
    """
    try:
        print(f"🔍 Starting scan for system: {system_id}")

        # Step 1: Collect system data
        assessment_data = data_collector.perform_full_assessment(system_id)
        print(f"✅ Data collection complete")

        # Step 2: Calculate risk score
        risk_result = risk_engine.calculate_overall_risk(assessment_data)
        print(f"⚠️ Risk score: {risk_result['risk_score']}")

        # Step 3: ML prediction
        ml_prediction = ml_detector.predict_threat(assessment_data)
        print(f"🤖 ML prediction complete")

        # Step 4: Get recommendations
        recommendations = risk_engine.get_recommendations(
            assessment_data,
            risk_result["components"]
        )

        # Step 5: Generate alerts
        alerts = alert_system.check_and_generate_alerts(
            assessment_data,
            risk_result
        )

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

        # Step 6: Save to database
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
        )
        db.add(db_risk_result)

        # Save alerts
        for alert in alerts:
            db_alert = Alert(
                **alert,
                assessment_id=db_assessment.id,
                created_date=datetime.utcnow()
            )
            db.add(db_alert)

        db.commit()
        print(f"💾 Data saved to database successfully")

        # ===============================
        # PREPARE RESPONSE
        # ===============================

        response = {
            "success": True,
            "system_id": system_id,
            "assessment_date": db_assessment.assessment_date.isoformat(),
            "assessment_id": db_assessment.id,
            "risk_score": risk_result["risk_score"],
            "threat_level": risk_result["threat_level"],
            "ml_prediction": {
                "threat_probability": ml_prediction.get("threat_probability", 0),
                "confidence": ml_prediction.get("confidence", 0),
                "predicted_class": ml_prediction.get("predicted_class", "unknown")
            },
            "detected_issues": [
                {
                    "category": key.replace("_", " ").title(),
                    "value": value,
                    "severity": "high" if value > 70 else "medium" if value > 30 else "low"
                }
                for key, value in risk_result.get("components", {}).items()
                if value > 30
            ],
            "recommendations": recommendations,
            "alerts_count": len(alerts),
            "alerts": alerts[:10],  # Limit to first 10 alerts
            "raw_data": assessment_data
        }

        print(f"✅ Scan completed successfully for {system_id}")
        return response

    except Exception as e:
        print(f"❌ SCAN ERROR: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)}"
        )


# ===============================
# RISK SCORE ENDPOINT
# ===============================

@app.get("/api/risk-score/{system_id}")
async def get_risk_score(
    system_id: str,
    db: Session = Depends(get_db)
):
    """Get latest risk score for a system"""
    try:
        assessment = db.query(SystemAssessment).filter(
            SystemAssessment.system_id == system_id
        ).order_by(SystemAssessment.assessment_date.desc()).first()

        if not assessment:
            raise HTTPException(
                status_code=404,
                detail=f"No assessments found for system: {system_id}"
            )

        risk_result = db.query(RiskResult).filter(
            RiskResult.assessment_id == assessment.id
        ).first()

        return {
            "success": True,
            "system_id": system_id,
            "risk_score": risk_result.risk_score if risk_result else None,
            "threat_level": risk_result.threat_level if risk_result else None,
            "assessment_date": assessment.assessment_date.isoformat(),
            "assessment_id": assessment.id
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching risk score: {str(e)}"
        )


# ===============================
# ASSESSMENT HISTORY ENDPOINT
# ===============================

@app.get("/api/history/{system_id}")
async def get_assessment_history(
    system_id: str,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """Get assessment history for a system (last N assessments)"""
    try:
        # Validate limit
        if limit > 100:
            limit = 100
        if limit < 1:
            limit = 10

        assessments = db.query(SystemAssessment).filter(
            SystemAssessment.system_id == system_id
        ).order_by(SystemAssessment.assessment_date.desc()).limit(limit).all()

        if not assessments:
            return {
                "success": True,
                "system_id": system_id,
                "history": [],
                "total": 0
            }

        history = []
        for assessment in assessments:
            risk_result = db.query(RiskResult).filter(
                RiskResult.assessment_id == assessment.id
            ).first()

            history.append({
                "assessment_id": assessment.id,
                "date": assessment.assessment_date.isoformat(),
                "risk_score": risk_result.risk_score if risk_result else None,
                "threat_level": risk_result.threat_level if risk_result else None,
                "failed_logins": assessment.failed_logins,
                "open_ports": assessment.open_ports,
                "malware_indicators": assessment.malware_indicators
            })

        return {
            "success": True,
            "system_id": system_id,
            "history": history,
            "total": len(history)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching history: {str(e)}"
        )


# ===============================
# DASHBOARD ENDPOINT
# ===============================

@app.get("/api/dashboard")
async def get_dashboard(db: Session = Depends(get_db)):
    """Get dashboard summary with latest assessments"""
    try:
        # Get latest assessments
        assessments = db.query(SystemAssessment).order_by(
            SystemAssessment.assessment_date.desc()
        ).limit(5).all()

        # Get critical alerts
        critical_alerts = db.query(Alert).filter(
            Alert.severity == "critical"
        ).order_by(Alert.created_date.desc()).limit(10).all()

        dashboard_data = {
            "success": True,
            "total_systems": len(set(a.system_id for a in assessments)),
            "recent_assessments": [
                {
                    "system_id": a.system_id,
                    "date": a.assessment_date.isoformat(),
                    "failed_logins": a.failed_logins,
                    "open_ports": a.open_ports,
                    "malware_indicators": a.malware_indicators
                }
                for a in assessments
            ],
            "critical_alerts": [
                {
                    "id": alert.id,
                    "message": alert.message,
                    "severity": alert.severity,
                    "created": alert.created_date.isoformat() if alert.created_date else None,
                    "resolved": alert.is_resolved
                }
                for alert in critical_alerts
            ],
            "last_updated": datetime.utcnow().isoformat()
        }

        return dashboard_data
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching dashboard: {str(e)}"
        )


# ===============================
# ALERT MANAGEMENT ENDPOINTS
# ===============================

@app.post("/api/alerts/resolve/{alert_id}")
async def resolve_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """Mark an alert as resolved"""
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()

        if not alert:
            raise HTTPException(
                status_code=404,
                detail=f"Alert {alert_id} not found"
            )

        alert.is_resolved = True
        db.commit()

        return {
            "success": True,
            "message": "Alert resolved successfully",
            "alert_id": alert_id
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error resolving alert: {str(e)}"
        )


@app.get("/api/alerts")
async def get_all_alerts(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Get all alerts with pagination"""
    try:
        if limit > 200:
            limit = 200
        if limit < 1:
            limit = 20

        alerts = db.query(Alert).order_by(
            Alert.created_date.desc()
        ).limit(limit).all()

        return {
            "success": True,
            "total": len(alerts),
            "alerts": [
                {
                    "id": alert.id,
                    "message": alert.message,
                    "severity": alert.severity,
                    "created": alert.created_date.isoformat() if alert.created_date else None,
                    "resolved": alert.is_resolved
                }
                for alert in alerts
            ]
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching alerts: {str(e)}"
        )


# ===============================
# ERROR HANDLERS
# ===============================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return {
        "success": False,
        "error": exc.detail,
        "status_code": exc.status_code
    }


# ===============================
# MAIN ENTRY POINT
# ===============================

if __name__ == "__main__":
    # Get host and port from environment or use defaults
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    
    print(f"🚀 Starting Cyber Risk Assessment API on {host}:{port}")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )
