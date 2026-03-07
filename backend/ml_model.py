import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

class MLThreatDetector:
    def __init__(self, model_path=None):
        self.model_path = model_path or "models/threat_model.pkl"
        self.scaler_path = "models/scaler.pkl"
        self.model = None
        self.scaler = None
        self.anomaly_detector = None
       
    def create_synthetic_training_data(self, n_samples=1000):
        """Create synthetic training data for demonstration"""
        np.random.seed(42)
       
        data = {
            'password_strength': np.random.randint(0, 101, n_samples),
            'failed_logins': np.random.poisson(5, n_samples),
            'open_ports': np.random.poisson(3, n_samples),
            'critical_ports': np.random.poisson(1, n_samples),
            'firewall_enabled': np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),
            'patches_missing': np.random.poisson(2, n_samples),
            'suspicious_ips': np.random.poisson(0.5, n_samples),
            'traffic_anomaly_score': np.random.uniform(0, 1, n_samples),
            'malware_indicators': np.random.poisson(0.2, n_samples)
        }
       
        df = pd.DataFrame(data)
       
        # Generate threat labels (1 for high threat, 0 for low)
        threat_score = (
            (100 - df['password_strength']) / 100 * 0.2 +
            (df['failed_logins'] > 10) * 0.15 +
            (df['critical_ports'] > 0) * 0.25 +
            (df['patches_missing'] > 5) * 0.15 +
            (df['suspicious_ips'] > 0) * 0.15 +
            (df['traffic_anomaly_score'] > 0.7) * 0.1
        )
       
        df['threat_label'] = (threat_score > 0.4).astype(int)
       
        return df
   
    def train_model(self):
        """Train the ML model for threat prediction"""
        # Create training data
        df = self.create_synthetic_training_data(2000)
       
        # Prepare features
        feature_cols = ['password_strength', 'failed_logins', 'open_ports',
                       'critical_ports', 'firewall_enabled', 'patches_missing',
                       'suspicious_ips', 'traffic_anomaly_score', 'malware_indicators']
       
        X = df[feature_cols]
        y = df['threat_label']
       
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
       
        # Train Random Forest classifier
        self.model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        self.model.fit(X_scaled, y)
       
        # Train Isolation Forest for anomaly detection
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.anomaly_detector.fit(X_scaled)
       
        # Save models
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        joblib.dump(self.anomaly_detector, "models/anomaly_detector.pkl")
       
        print("Models trained and saved successfully")
       
    def load_models(self):
        """Load trained models"""
        try:
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            self.anomaly_detector = joblib.load("models/anomaly_detector.pkl")
            print("Models loaded successfully")
        except:
            print("Models not found. Training new models...")
            self.train_model()
   
    def predict_threat(self, assessment_data):
        """Predict threat probability using ML"""
        if self.model is None:
            self.load_models()
       
        # Prepare features
        feature_cols = ['password_strength', 'failed_logins', 'open_ports',
                       'critical_ports', 'firewall_enabled', 'patches_missing',
                       'suspicious_ips', 'traffic_anomaly_score', 'malware_indicators']
       
        # Extract features from assessment data
        features = []
        for col in feature_cols:
            if col == 'firewall_enabled':
                features.append(1 if assessment_data.get(col, False) else 0)
            else:
                features.append(assessment_data.get(col, 0))
       
        # Scale features
        features_scaled = self.scaler.transform([features])
       
        # Predict probability
        threat_probability = self.model.predict_proba(features_scaled)[0][1]
       
        # Detect anomalies
        is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
       
        return {
            "threat_probability": float(threat_probability),
            "is_anomaly": bool(is_anomaly),
            "prediction": "HIGH_RISK" if threat_probability > 0.7 else "MEDIUM_RISK" if threat_probability > 0.3 else "LOW_RISK"
        }