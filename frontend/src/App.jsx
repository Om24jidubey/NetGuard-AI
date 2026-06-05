import React, { useState } from "react";
import Dashboard from "./Dashboard";
import ChatPanel from "./ChatPanel";
import "./index.css";
import logo from "./netguard-navbar-logo.svg";
export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard");

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
            className={`nav-tab ${activeTab === "chat" ? "active" : ""}`}
            onClick={() => setActiveTab("chat")}
          >
            AI Assistant
          </button>
        </div>
        <div className="nav-status">
          <span className="status-dot"></span>
          <span className="status-text">Live Monitoring</span>
        </div>
      </nav>

      <main className="main-content">
        {activeTab === "dashboard" ? <Dashboard /> : <ChatPanel />}
      </main>
    </div>
  );
}