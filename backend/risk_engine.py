import numpy as np
from typing import Dict, Any

class RiskEngine:
    def __init__(self):
        # Define weights for different risk factors
        self.weights = {
            "password_risk": 0.20,
            "authentication_risk": 0.15,
            "network_risk": 0.25,
            "patch_risk": 0.15,
            "malware_risk": 0.15,
            "traffic_risk": 0.10
        }
        
    def calculate_password_risk(self, assessment_data: Dict[str, Any]) -> float:
        """Calculate risk from password strength"""
        password_strength = assessment_data.get("password_strength", 50)
        return max(0, 100 - password_strength)
    
    def calculate_authentication_risk(self, assessment_data: Dict[str, Any]) -> float:
        """Calculate risk from failed login attempts"""
        failed_logins = assessment_data.get("failed_logins", 0)
        
        if failed_logins == 0:
            return 0
        elif failed_logins < 5:
            return 30
        elif failed_logins < 15:
            return 60
        elif failed_logins < 30:
            return 80
        else:
            return 100
    
    def calculate_network_risk(self, assessment_data: Dict[str, Any]) -> float:
        """Calculate risk from network exposure"""
        open_ports = assessment_data.get("open_ports", 0)
        critical_ports = assessment_data.get("critical_ports", 0)
        firewall_enabled = assessment_data.get("firewall_enabled", False)
        
        # Base risk from open ports
        port_risk = min(open_ports * 5, 50)
        
        # Additional risk from critical ports
        critical_risk = min(critical_ports * 15, 50)
        
        # Reduce risk if firewall is enabled
        firewall_benefit = 20 if firewall_enabled else 0
        
        total_risk = port_risk + critical_risk - firewall_benefit
        return max(0, min(100, total_risk))
    
    def calculate_patch_risk(self, assessment_data: Dict[str, Any]) -> float:
        """Calculate risk from missing patches"""
        patches_missing = assessment_data.get("patches_missing", 0)
        
        if patches_missing == 0:
            return 0
        elif patches_missing < 3:
            return 25
        elif patches_missing < 7:
            return 50
        elif patches_missing < 15:
            return 75
        else:
            return 100
    
    def calculate_malware_risk(self, assessment_data: Dict[str, Any]) -> float:
        """Calculate risk from malware indicators"""
        malware_indicators = assessment_data.get("malware_indicators", 0)
        antivirus_enabled = assessment_data.get("antivirus_enabled", False)
        
        indicator_risk = min(malware_indicators * 25, 80)
        antivirus_benefit = 20 if antivirus_enabled else 0
        
        return max(0, min(100, indicator_risk - antivirus_benefit))
    
    def calculate_traffic_risk(self, assessment_data: Dict[str, Any]) -> float:
        """Calculate risk from traffic anomalies"""
        traffic_anomaly = assessment_data.get("traffic_anomaly_score", 0)
        suspicious_ips = assessment_data.get("suspicious_ips", 0)
        
        anomaly_risk = traffic_anomaly * 70
        ip_risk = min(suspicious_ips * 10, 30)
        
        return min(100, anomaly_risk + ip_risk)
    
    def calculate_overall_risk(self, assessment_data: Dict[str, Any]) -> Dict[str, float]:
        """Calculate overall risk score"""
        
        # Calculate individual risk components
        password_risk = self.calculate_password_risk(assessment_data)
        auth_risk = self.calculate_authentication_risk(assessment_data)
        network_risk = self.calculate_network_risk(assessment_data)
        patch_risk = self.calculate_patch_risk(assessment_data)
        malware_risk = self.calculate_malware_risk(assessment_data)
        traffic_risk = self.calculate_traffic_risk(assessment_data)
        
        # Calculate weighted score
        risk_score = (
            self.weights["password_risk"] * password_risk +
            self.weights["authentication_risk"] * auth_risk +
            self.weights["network_risk"] * network_risk +
            self.weights["patch_risk"] * patch_risk +
            self.weights["malware_risk"] * malware_risk +
            self.weights["traffic_risk"] * traffic_risk
        )
        
        # Determine threat level
        if risk_score < 30:
            threat_level = "LOW"
        elif risk_score < 60:
            threat_level = "MEDIUM"
        else:
            threat_level = "HIGH"
        
        return {
            "risk_score": round(risk_score, 2),
            "threat_level": threat_level,
            "components": {
                "password_risk": password_risk,
                "authentication_risk": auth_risk,
                "network_risk": network_risk,
                "patch_risk": patch_risk,
                "malware_risk": malware_risk,
                "traffic_risk": traffic_risk
            }
        }
    
    def get_recommendations(self, assessment_data: Dict[str, Any], risk_components: Dict[str, float]) -> list:
        """Generate security recommendations based on risk factors"""
        recommendations = []
        
        # Password recommendations
        if risk_components["password_risk"] > 50:
            recommendations.append({
                "priority": "HIGH",
                "category": "Authentication",
                "title": "Weak Password Policy",
                "description": "Implement strong password policy requiring minimum 12 characters with mixed case, numbers, and special characters",
                "action": "Enforce password complexity requirements"
            })
        
        # Authentication recommendations
        if risk_components["authentication_risk"] > 40:
            recommendations.append({
                "priority": "HIGH",
                "category": "Authentication",
                "title": "Multiple Failed Login Attempts",
                "description": f"{assessment_data.get('failed_logins', 0)} failed login attempts detected",
                "action": "Enable account lockout after 5 failed attempts and implement MFA"
            })
        
        # Network recommendations
        if risk_components["network_risk"] > 40:
            if assessment_data.get("critical_ports", 0) > 0:
                recommendations.append({
                    "priority": "CRITICAL",
                    "category": "Network Security",
                    "title": "Critical Ports Exposed",
                    "description": f"Exposed critical ports: {assessment_data.get('critical_ports', 0)}",
                    "action": "Close unnecessary ports and implement firewall rules"
                })
            
            if not assessment_data.get("firewall_enabled", False):
                recommendations.append({
                    "priority": "HIGH",
                    "category": "Network Security",
                    "title": "Firewall Disabled",
                    "description": "System firewall is currently disabled",
                    "action": "Enable system firewall immediately"
                })
        
        # Patch recommendations
        if risk_components["patch_risk"] > 30:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "System Updates",
                "title": "Missing Security Patches",
                "description": f"{assessment_data.get('patches_missing', 0)} security updates missing",
                "action": "Apply all critical security patches"
            })
        
        # Malware recommendations
        if risk_components["malware_risk"] > 30:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Malware Protection",
                "title": "Potential Malware Detected",
                "description": f"{assessment_data.get('malware_indicators', 0)} suspicious processes detected",
                "action": "Run full system antivirus scan and investigate suspicious processes"
            })
        
        # Traffic recommendations
        if risk_components["traffic_risk"] > 40:
            recommendations.append({
                "priority": "HIGH",
                "category": "Network Monitoring",
                "title": "Suspicious Network Activity",
                "description": f"Traffic anomaly score: {assessment_data.get('traffic_anomaly_score', 0):.2f}",
                "action": "Monitor network traffic and block suspicious IPs"
            })
        
        # General recommendations if everything looks good
        if len(recommendations) == 0:
            recommendations.append({
                "priority": "LOW",
                "category": "General",
                "title": "System Security Status",
                "description": "System appears to be well-secured",
                "action": "Continue regular security monitoring"
            })
        
        return recommendations