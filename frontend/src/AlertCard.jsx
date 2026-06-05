import React from "react";

const SEVERITY_COLORS = {
  critical: "#e24b4a",
  high:     "#ef9f27",
  medium:   "#378add",
  low:      "#1d9e75",
  normal:   "#888780",
};

export default function AlertCard({ alert, onExplain }) {
  const color = SEVERITY_COLORS[alert.severity] || "#888";

  return (
    <div className="alert-card" style={{ borderLeft: `4px solid ${color}` }}>
      <div className="alert-left">
        <span className="alert-type">{alert.type}</span>
        <span className="alert-ip">Source IP: {alert.ip}</span>
        <span className="alert-time">{alert.time}</span>
      </div>
      <div className="alert-right">
        <span
          className="severity-badge"
          style={{ background: color + "22", color }}
        >
          {alert.severity?.toUpperCase()}
        </span>
        <span className="alert-score">score: {alert.score?.toFixed(3)}</span>
        <button className="explain-btn" onClick={onExplain}>
          🤖 Explain
        </button>
      </div>
    </div>
  );
}