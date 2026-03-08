import { useEffect } from "react";
import RiskScoreCard from './RiskScoreCard';
import ThreatIndicators from './ThreatIndicators';
import Recommendations from './Recommendations';
import RiskTrendChart from './RiskTrendChart';
import { FiRefreshCw } from 'react-icons/fi';


const Dashboard = ({ assessmentData, history, onScan, loading }) => {

  useEffect(() => {
    const interval = setInterval(() => {
      onScan();
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  if (!assessmentData) {
    return <div className="loading">Loading security data...</div>;
  }


  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>Cyber Threat Risk Dashboard</h2>
        <button 
          className="scan-button" 
          onClick={onScan}
          disabled={loading}
        >
          <FiRefreshCw className={loading ? 'spin' : ''} />
          {loading ? 'Scanning...' : 'Run New Scan'}
        </button>
      </div>

      <div className="dashboard-grid">
        <div className="grid-item score-panel">
          <RiskScoreCard 
            score={assessmentData.risk_score}
            level={assessmentData.threat_level}
            assessmentData={assessmentData}
          />
        </div>

        <div className="grid-item indicators-panel">
          <ThreatIndicators 
            detectedIssues={assessmentData.detected_issues}
            rawData={assessmentData.raw_data}
          />
        </div>

        <div className="grid-item recommendations-panel">
          <Recommendations recommendations={assessmentData.recommendations} />
        </div>

        <div className="grid-item trend-panel">
          <h3>Risk Trend</h3>
          <RiskTrendChart data={history} />
        </div>
      </div>

      <div className="recent-alerts">
        <h3>Recent Alerts</h3>
        <div className="alerts-list">
          {assessmentData.alerts && assessmentData.alerts.length > 0 ? (
            assessmentData.alerts.map((alert, index) => (
              <div key={index} className={`alert-item ${alert.severity.toLowerCase()}`}>
                <div className="alert-icon">⚠️</div>
                <div className="alert-content">
                  <div className="alert-title">{alert.alert_type}</div>
                  <div className="alert-description">{alert.description}</div>
                  <div className="alert-time">{new Date(alert.timestamp).toLocaleString()}</div>
                </div>
                <div className="alert-severity">{alert.severity}</div>
              </div>
            ))
          ) : (
            <div className="no-alerts">No active alerts</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;