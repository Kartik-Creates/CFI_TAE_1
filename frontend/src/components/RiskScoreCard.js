import React from 'react';

const RiskScoreCard = ({ score, level, assessmentData }) => {

  const getScoreColor = (score) => {
    if (score < 30) return '#00ff9d';
    if (score < 60) return '#ffd700';
    return '#ff4d4d';
  };

  const getLevelColor = (level) => {
    switch(level) {
      case 'LOW': return '#00ff9d';
      case 'MEDIUM': return '#ffd700';
      case 'HIGH': return '#ff4d4d';
      default: return '#ffffff';
    }
  };

  return (
    <div className="risk-score-card">

      <div className="score-header">
        <h3>System Risk Score</h3>
        <div className="system-id">host-01</div>
      </div>

      <div className="score-display">
        <div 
          className="score-circle"
          style={{
            borderColor: getScoreColor(score),
            color: getScoreColor(score)
          }}
        >
          <span className="score-value">{score}</span>
          <span className="score-max">/100</span>
        </div>

        <div 
          className="threat-level"
          style={{ color: getLevelColor(level) }}
        >
          {level} RISK
        </div>
      </div>

      <div className="score-details">

        <div className="detail-item">
          <span className="detail-label">ML Prediction</span>
          <span className="detail-value">
            {((assessmentData?.ml_prediction?.threat_probability || 0) * 100).toFixed(1)}%
          </span>
        </div>

        <div className="detail-item">
          <span className="detail-label">Anomaly Detected</span>
          <span className="detail-value">
            {assessmentData?.ml_prediction?.is_anomaly ? 'Yes' : 'No'}
          </span>
        </div>

      </div>

    </div>
  );
};

export default RiskScoreCard;