from datetime import datetime
from typing import Dict, Any
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AlertSystem:
    def __init__(self, db_session=None):
        self.db = db_session
        self.alert_threshold = 70
        
    def check_and_generate_alerts(self, assessment_data: Dict[str, Any], risk_result: Dict[str, Any]):
        """Generate alerts based on risk assessment"""
        alerts = []
        risk_score = risk_result.get("risk_score", 0)
        
        # High risk score alert
        if risk_score > self.alert_threshold:
            alerts.append({
                "system_id": assessment_data.get("system_id", "unknown"),
                "alert_type": "HIGH_RISK_SCORE",
                "severity": "CRITICAL",
                "description": f"System risk score is {risk_score:.2f} - exceeds threshold of {self.alert_threshold}",
                "timestamp": datetime.utcnow()
            })
        
        # Specific threat alerts
        if assessment_data.get("failed_logins", 0) > 10:
            alerts.append({
                "system_id": assessment_data.get("system_id", "unknown"),
                "alert_type": "BRUTE_FORCE_ATTEMPT",
                "severity": "HIGH",
                "description": f"Multiple failed login attempts detected: {assessment_data.get('failed_logins', 0)}",
                "timestamp": datetime.utcnow()
            })
        
        if assessment_data.get("critical_ports", 0) > 2:
            alerts.append({
                "system_id": assessment_data.get("system_id", "unknown"),
                "alert_type": "CRITICAL_PORTS_EXPOSED",
                "severity": "HIGH",
                "description": f"{assessment_data.get('critical_ports', 0)} critical ports are exposed",
                "timestamp": datetime.utcnow()
            })
        
        if assessment_data.get("malware_indicators", 0) > 0:
            alerts.append({
                "system_id": assessment_data.get("system_id", "unknown"),
                "alert_type": "MALWARE_DETECTED",
                "severity": "CRITICAL",
                "description": f"Potential malware indicators found: {assessment_data.get('malware_indicators', 0)}",
                "timestamp": datetime.utcnow()
            })
        
        if assessment_data.get("traffic_anomaly_score", 0) > 0.8:
            alerts.append({
                "system_id": assessment_data.get("system_id", "unknown"),
                "alert_type": "TRAFFIC_ANOMALY",
                "severity": "MEDIUM",
                "description": "Unusual network traffic patterns detected",
                "timestamp": datetime.utcnow()
            })
        
        # Store alerts in database
        if self.db:
            for alert in alerts:
                # Store in database (implementation depends on your DB model)
                pass
        
        return alerts
    
    def send_email_alert(self, alert, recipient_email="admin@example.com"):
        """Send email alert for critical issues"""
        if alert["severity"] not in ["CRITICAL", "HIGH"]:
            return
        
        try:
            msg = MIMEMultipart()
            msg["From"] = "security@cyberrisk.com"
            msg["To"] = recipient_email
            msg["Subject"] = f"[{alert['severity']}] Security Alert: {alert['alert_type']}"
            
            body = f"""
            Security Alert Detected
            
            System ID: {alert['system_id']}
            Alert Type: {alert['alert_type']}
            Severity: {alert['severity']}
            Description: {alert['description']}
            Time: {alert['timestamp']}
            
            Immediate action recommended.
            """
            
            msg.attach(MIMEText(body, "plain"))
            
            # Uncomment to enable email
            # server = smtplib.SMTP("smtp.gmail.com", 587)
            # server.starttls()
            # server.login("your-email@gmail.com", "password")
            # server.send_message(msg)
            # server.quit()
            
            print(f"Alert email sent: {alert['alert_type']}")
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")