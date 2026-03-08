import React from 'react';

const Recommendations = ({ recommendations }) => {
  const getPriorityColor = (priority) => {
    switch(priority) {
      case 'CRITICAL': return '#ff4d4d';
      case 'HIGH': return '#ff8c4d';
      case 'MEDIUM': return '#ffd700';
      case 'LOW': return '#00ff9d';
      default: return '#ffffff';
    }
  };

  const getPriorityIcon = (priority) => {
    switch(priority) {
      case 'CRITICAL': return '🔴';
      case 'HIGH': return '🟠';
      case 'MEDIUM': return '🟡';
      case 'LOW': return '🟢';
      default: return '⚪';
    }
  };

  return (
    <div className="recommendations">
      <h3>Security Recommendations</h3>
      
      <div className="recommendations-list">
        {recommendations && recommendations.length > 0 ? (
          recommendations.map((rec, index) => (
            <div key={index} className="recommendation-item">
              <div className="recommendation-header">
                <span className="priority-icon">{getPriorityIcon(rec.priority)}</span>
                <span 
                  className="priority-badge"
                  style={{ backgroundColor: getPriorityColor(rec.priority) }}
                >
                  {rec.priority}
                </span>
                <span className="recommendation-category">{rec.category}</span>
              </div>
              
              <div className="recommendation-content">
                <h4>{rec.title}</h4>
                <p className="recommendation-description">{rec.description}</p>
                <div className="recommendation-action">
                  <span className="action-label">Action required:</span>
                  <span className="action-text">{rec.action}</span>
                </div>
              </div>
              
              <div className="recommendation-footer">
                <button className="implement-btn">Mark as Implemented</button>
                <button className="ignore-btn">Ignore</button>
              </div>
            </div>
          ))
        ) : (
          <div className="no-recommendations">
            <div className="success-icon">✓</div>
            <p>No recommendations at this time. System is well-secured.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Recommendations;