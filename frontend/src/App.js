import React, { useState, useEffect } from "react";
import Dashboard from "./components/Dashboard";
import SystemScanner from "./components/SystemScanner";
import RiskTrendChart from "./components/RiskTrendChart";
import axios from "axios";

/*
API URL from Vercel environment variable
Fallback keeps local development working
*/
const API_BASE_URL =
  process.env.REACT_APP_API_URL || "http://localhost:8000/api";

function App() {
  const [currentView, setCurrentView] = useState("dashboard");
  const [assessmentData, setAssessmentData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);

  const performScan = async () => {
    setLoading(true);
    setError(null);

    try {
      const scanResponse = await axios.get(`${API_BASE_URL}/scan`, {
        params: { system_id: "host-01" },
      });

      if (scanResponse?.data) {
        setAssessmentData(scanResponse.data);
      }

      const historyResponse = await axios.get(
        `${API_BASE_URL}/history/host-01`,
        {
          params: { limit: 10 },
        }
      );

      if (historyResponse?.data?.history) {
        setHistory(historyResponse.data.history);
      } else {
        setHistory([]);
      }
    } catch (err) {
      console.error("Scan failed:", err);
      setError("Failed to perform security scan");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    performScan();
  }, []);

 return (
  <div className="app">

    <div className="layout">

      <nav className="sidebar">
        <div className="logo">
          <h1>
            CyberRisk<span>Pro</span>
          </h1>
        </div>

        <ul className="nav-menu">
          <li
            className={currentView === "dashboard" ? "active" : ""}
            onClick={() => setCurrentView("dashboard")}
          >
            <span>Dashboard</span>
          </li>

          <li
            className={currentView === "scanner" ? "active" : ""}
            onClick={() => setCurrentView("scanner")}
          >
            <span>System Scanner</span>
          </li>

          <li
            className={currentView === "reports" ? "active" : ""}
            onClick={() => setCurrentView("reports")}
          >
            <span>Reports</span>
          </li>

          <li
            className={currentView === "alerts" ? "active" : ""}
            onClick={() => setCurrentView("alerts")}
          >
            <span>Alerts</span>
          </li>

          <li
            className={currentView === "settings" ? "active" : ""}
            onClick={() => setCurrentView("settings")}
          >
            <span>Settings</span>
          </li>
        </ul>

        <div className="system-status">
          <div className="status-indicator online"></div>
          <span>System Online</span>
        </div>
      </nav>

      <main className="main-content">
        {currentView === "dashboard" && (
          <Dashboard
            assessmentData={assessmentData}
            history={history}
            onScan={performScan}
            loading={loading}
          />
        )}

        {currentView === "scanner" && (
          <SystemScanner
            onScan={performScan}
            loading={loading}
            scanResult={assessmentData}
          />
        )}

        {currentView === "reports" && (
          <div className="reports-view">
            <h2>Security Reports</h2>
            <RiskTrendChart data={history} />
          </div>
        )}

        {currentView === "alerts" && (
          <div className="alerts-view">
            <h2>Alerts</h2>
            <p>No alert viewer implemented yet.</p>
          </div>
        )}

        {currentView === "settings" && (
          <div className="settings-view">
            <h2>Settings</h2>
            <p>Settings panel coming soon.</p>
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

    <footer className="app-footer">
      Built and deployed by <strong>Kartik Tamhan</strong> and <strong>Harsh Buwade</strong>
    </footer>

  </div>
);
