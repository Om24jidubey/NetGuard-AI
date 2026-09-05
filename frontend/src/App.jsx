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
import logo from "./netguard-navbar-logo.svg";

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
          <img src={logo} alt="NetGuard AI" width="32" height="32" style={{ display: "block" }} />
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