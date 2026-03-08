import React, { useState, useEffect } from 'react';
import Dashboard from './components/Dashboard';
import SystemScanner from './components/SystemScanner';
import RiskScoreCard from './components/RiskScoreCard';
import ThreatIndicators from './components/ThreatIndicators';
import Recommendations from './components/Recommendations';
import RiskTrendChart from './components/RiskTrendChart';
import axios from 'axios';

const API_BASE_URL = 'https://cyber-risk-backend.onrender.com/api';

function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [assessmentData, setAssessmentData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);

  const performScan = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await axios.post(`${API_BASE_URL}/scan?system_id=host-01`);
      setAssessmentData(response.data);
      
      // Fetch updated history
      const historyResponse = await axios.get(`${API_BASE_URL}/history/host-01?limit=10`);
      setHistory(historyResponse.data);
      
    } catch (err) {
      setError('Failed to perform security scan');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Load initial data
    performScan();
  }, []);

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="logo">
          <h1>CyberRisk<span>Pro</span></h1>
        </div>
        <ul className="nav-menu">
          <li className={currentView === 'dashboard' ? 'active' : ''} 
              onClick={() => setCurrentView('dashboard')}>
            <i className="icon-dashboard"></i>
            <span>Dashboard</span>
          </li>
          <li className={currentView === 'scanner' ? 'active' : ''} 
              onClick={() => setCurrentView('scanner')}>
            <i className="icon-scan"></i>
            <span>System Scanner</span>
          </li>
          <li className={currentView === 'reports' ? 'active' : ''} 
              onClick={() => setCurrentView('reports')}>
            <i className="icon-reports"></i>
            <span>Reports</span>
          </li>
          <li className={currentView === 'alerts' ? 'active' : ''} 
              onClick={() => setCurrentView('alerts')}>
            <i className="icon-alerts"></i>
            <span>Alerts</span>
          </li>
          <li className={currentView === 'settings' ? 'active' : ''} 
              onClick={() => setCurrentView('settings')}>
            <i className="icon-settings"></i>
            <span>Settings</span>
          </li>
        </ul>
        <div className="system-status">
          <div className="status-indicator online"></div>
          <span>System Online</span>
        </div>
      </nav>

      <main className="main-content">
        {currentView === 'dashboard' && (
          <Dashboard 
            assessmentData={assessmentData}
            history={history}
            onScan={performScan}
            loading={loading}
          />
        )}
        
        {currentView === 'scanner' && (
          <SystemScanner 
            onScan={performScan}
            loading={loading}
            scanResult={assessmentData}
          />
        )}
        
        {currentView === 'reports' && (
          <div className="reports-view">
            <h2>Security Reports</h2>
            <RiskTrendChart data={history} />
          </div>
        )}
        
        {error && (
          <div className="error-alert">
            <span>{error}</span>
            <button onClick={performScan}>Retry</button>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
