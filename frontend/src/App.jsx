/**
 * Root Application Container — NetGuard AI
 * This is the main entry point for the React frontend. It manages top-level routing
 * across the main dashboard tabs (Analytics, Live Capture, AI Assistant) and maintains
 * global application state.
 */
import React, { useState, useEffect } from "react";
import Dashboard from "./Dashboard";
import ChatPanel from "./ChatPanel";
import LivePanel from "./LivePanel";
import "./index.css";
const NetGuardLogo = () => (
  <svg width="32" height="32" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" style={{ display: "block" }}>
    <path d="M16,2 L26,6 L26,18 Q26,26 16,30 Q6,26 6,18 L6,6 Z" fill="#0D1F3C" stroke="#00D4FF" strokeWidth="1.2"/>
    <line x1="9" y1="12" x2="12" y2="12" stroke="#00D4FF" strokeWidth="0.7" fill="none" opacity="0.6"/>
    <line x1="12" y1="12" x2="12" y2="14" stroke="#00D4FF" strokeWidth="0.7" fill="none" opacity="0.6"/>
    <line x1="20" y1="12" x2="23" y2="12" stroke="#00D4FF" strokeWidth="0.7" fill="none" opacity="0.6"/>
    <line x1="20" y1="12" x2="20" y2="14" stroke="#00D4FF" strokeWidth="0.7" fill="none" opacity="0.6"/>
    <line x1="12" y1="14" x2="20" y2="14" stroke="#00D4FF" strokeWidth="0.7" fill="none" opacity="0.9"/>
    <ellipse cx="16" cy="17" rx="5" ry="3.5" fill="#0A1628" stroke="#00D4FF" strokeWidth="1"/>
    <circle cx="16" cy="17" r="2.8" fill="#00C896"/>
    <circle cx="16" cy="17" r="1.6" fill="#0A1628"/>
    <circle cx="16" cy="17" r="0.7" fill="#00D4FF"/>
    <circle cx="14.5" cy="15.8" r="0.6" fill="white" opacity="0.8"/>
    <rect x="11" y="22" width="10" height="5" rx="1.5" fill="#00C896"/>
    <text x="16" y="26" textAnchor="middle" fontFamily="Helvetica Neue, Helvetica, Arial, sans-serif" fontSize="3.8" fontWeight="700" fill="#0A1628" letterSpacing="0.5">AI</text>
  </svg>
);

// Dynamically use relative paths for production on Hugging Face Spaces
const API = process.env.REACT_APP_API_URL || "";

export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [isLive, setIsLive] = useState(false);

  // Wipe the backend completely on browser refresh
  useEffect(() => {
    fetch(`${API}/reset-session`, { method: "POST" }).catch(console.error);
  }, []);

  return (
    <div className="app">
      <nav className="navbar">
        <div className="nav-brand">
          <NetGuardLogo />
          <span className="brand-name">NetGuard AI</span>
          <span className="brand-tag">Network Security</span>
        </div>
        <div className="nav-tabs">
          <button
            className={`nav-tab ${activeTab === "dashboard" ? "active" : ""}`}
            onClick={() => setActiveTab("dashboard")}
          >
            Dashboard
          </button>
          <button
            className={`nav-tab ${activeTab === "live" ? "active" : ""}`}
            onClick={() => setActiveTab("live")}
          >
            Live Capturing
          </button>
          <button
            className={`nav-tab ${activeTab === "chat" ? "active" : ""}`}
            onClick={() => setActiveTab("chat")}
          >
            AI Assistant
          </button>
        </div>
        <div className="nav-status">
          <span className={`status-dot ${!isLive ? "offline" : ""}`}></span>
          <span className="status-text">{isLive ? "Live Monitoring" : "System Standby"}</span>
        </div>
      </nav>

      <main className="main-content">
        <div style={{ display: activeTab === "dashboard" ? "block" : "none" }}>
          <Dashboard />
        </div>
        <div style={{ display: activeTab === "live" ? "block" : "none" }}>
          <LivePanel setIsLive={setIsLive} />
        </div>
        <div style={{ display: activeTab === "chat" ? "block" : "none" }}>
          <ChatPanel />
        </div>
      </main>
    </div>
  );
}