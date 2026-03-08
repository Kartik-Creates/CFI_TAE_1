import React, { useState } from 'react';
import { FiSettings, FiPlay, FiDownload, FiShare2 } from 'react-icons/fi';

const SystemScanner = ({ onScan, loading, scanResult }) => {
  const [scanConfig, setScanConfig] = useState({
    deepScan: false,
    networkScan: true,
    malwareScan: true,
    portScan: true,
    vulnerabilityScan: true
  });

  const handleConfigChange = (key) => {
    setScanConfig(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const handleExport = () => {
    const dataStr = JSON.stringify(scanResult, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = `security-scan-${new Date().toISOString()}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  return (
    <div className="system-scanner">
      <div className="scanner-header">
        <h2>System Security Scanner</h2>
        <div className="scanner-actions">
          <button className="action-btn" onClick={handleExport} disabled={!scanResult}>
            <FiDownload /> Export Report
          </button>
          <button className="action-btn">
            <FiShare2 /> Share
          </button>
        </div>
      </div>

      <div className="scanner-content">
        <div className="scanner-config">
          <h3>Scan Configuration</h3>
          <div className="config-options">
            <label className="config-option">
              <input 
                type="checkbox" 
                checked={scanConfig.deepScan}
                onChange={() => handleConfigChange('deepScan')}
              />
              <span className="option-label">Deep System Scan</span>
              <span className="option-desc">Comprehensive analysis of all system components</span>
            </label>
            
            <label className="config-option">
              <input 
                type="checkbox" 
                checked={scanConfig.networkScan}
                onChange={() => handleConfigChange('networkScan')}
              />
              <span className="option-label">Network Vulnerability Scan</span>
              <span className="option-desc">Scan open ports and network services</span>
            </label>
            
            <label className="config-option">
              <input 
                type="checkbox" 
                checked={scanConfig.malwareScan}
                onChange={() => handleConfigChange('malwareScan')}
              />
              <span className="option-label">Malware Detection</span>
              <span className="option-desc">Check for malware indicators and suspicious processes</span>
            </label>
            
            <label className="config-option">
              <input 
                type="checkbox" 
                checked={scanConfig.portScan}
                onChange={() => handleConfigChange('portScan')}
              />
              <span className="option-label">Port Analysis</span>
              <span className="option-desc">Detailed port scanning and service identification</span>
            </label>
            
            <label className="config-option">
              <input 
                type="checkbox" 
                checked={scanConfig.vulnerabilityScan}
                onChange={() => handleConfigChange('vulnerabilityScan')}
              />
              <span className="option-label">Vulnerability Assessment</span>
              <span className="option-desc">Check for known vulnerabilities and missing patches</span>
            </label>
          </div>

          <button 
            className="start-scan-btn"
            onClick={onScan}
            disabled={loading}
          >
            <FiPlay />
            {loading ? 'Scanning...' : 'Start Security Scan'}
          </button>
        </div>

        <div className="scan-preview">
          <h3>Scan Preview</h3>
          {loading ? (
            <div className="scanning-animation">
              <div className="scanner-spinner"></div>
              <p>Performing security scan...</p>
              <div className="scan-progress">
                <div className="progress-bar">
                  <div className="progress-fill"></div>
                </div>
                <span className="progress-text">Analyzing system security...</span>
              </div>
            </div>
          ) : scanResult ? (
            <div className="scan-result-preview">
              <div className="preview-header">
                <div className="preview-score">
                  <span className="preview-label">Risk Score</span>
                  <span className={`preview-value risk-${scanResult.threat_level.toLowerCase()}`}>
                    {scanResult.risk_score}
                  </span>
                </div>
                <div className="preview-level">
                  <span className="preview-label">Threat Level</span>
                  <span className={`preview-value level-${scanResult.threat_level.toLowerCase()}`}>
                    {scanResult.threat_level}
                  </span>
                </div>
                <div className="preview-time">
                  <span className="preview-label">Scan Time</span>
                  <span className="preview-value">
                    {new Date(scanResult.assessment_date).toLocaleString()}
                  </span>
                </div>
              </div>

              <div className="preview-stats">
                <div className="stat">
                  <span className="stat-value">{scanResult.raw_data.failed_logins}</span>
                  <span className="stat-label">Failed Logins</span>
                </div>
                <div className="stat">
                  <span className="stat-value">{scanResult.raw_data.open_ports}</span>
                  <span className="stat-label">Open Ports</span>
                </div>
                <div className="stat">
                  <span className="stat-value">{scanResult.raw_data.patches_missing}</span>
                  <span className="stat-label">Missing Patches</span>
                </div>
                <div className="stat">
                  <span className="stat-value">{scanResult.raw_data.malware_indicators}</span>
                  <span className="stat-label">Malware Indicators</span>
                </div>
              </div>

              <div className="preview-actions">
                <button className="view-full-report">View Full Report</button>
                <button className="schedule-scan">Schedule Regular Scans</button>
              </div>
            </div>
          ) : (
            <div className="no-scan">
              <FiSettings className="no-scan-icon" />
              <p>Configure and start a scan to see results</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SystemScanner;