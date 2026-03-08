import React from 'react';

const ThreatIndicators = ({ detectedIssues, rawData }) => {
  const getIndicatorIcon = (category) => {
    const icons = {
      'Password Risk': '🔑',
      'Authentication Risk': '🔐',
      'Network Risk': '🌐',
      'Patch Risk': '📦',
      'Malware Risk': '🦠',
      'Traffic Risk': '📡'
    };
    return icons[category] || '⚠️';
  };

  const getIndicatorColor = (value) => {
    if (value < 30) return '#00ff9d';
    if (value < 60) return '#ffd700';
    return '#ff4d4d';
  };

  return (
    <div className="threat-indicators">
      <h3>Detected Threat Indicators</h3>
      
      <div className="indicators-list">
        {detectedIssues && detectedIssues.length > 0 ? (
          detectedIssues.map((issue, index) => (
            <div key={index} className="indicator-item">
              <div className="indicator-icon">{getIndicatorIcon(issue.category)}</div>
              <div className="indicator-content">
                <div className="indicator-category">{issue.category}</div>
                <div className="indicator-value">
                  <div 
                    className="indicator-bar"
                    style={{
                      width: `${issue.value}%`,
                      backgroundColor: getIndicatorColor(issue.value)
                    }}
                  ></div>
                  <span className="indicator-percent">{issue.value}%</span>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="no-indicators">No threat indicators detected</div>
        )}
      </div>

      <div className="raw-metrics">
        <h4>System Metrics</h4>
        <div className="metrics-grid">
          <div className="metric">
            <span className="metric-label">Failed Logins</span>
            <span className="metric-value">{rawData?.failed_logins || 0}</span>
          </div>
          <div className="metric">
            <span className="metric-label">Open Ports</span>
            <span className="metric-value">{rawData?.open_ports || 0}</span>
          </div>
          <div className="metric">
            <span className="metric-label">Critical Ports</span>
            <span className="metric-value">{rawData?.critical_ports || 0}</span>
          </div>
          <div className="metric">
            <span className="metric-label">Missing Patches</span>
            <span className="metric-value">{rawData?.patches_missing || 0}</span>
          </div>
          <div className="metric">
            <span className="metric-label">Malware Indicators</span>
            <span className="metric-value">{rawData?.malware_indicators || 0}</span>
          </div>
          <div className="metric">
            <span className="metric-label">Suspicious IPs</span>
            <span className="metric-value">{rawData?.suspicious_ips || 0}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatIndicators;