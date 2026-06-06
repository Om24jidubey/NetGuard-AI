import React, { useState, useEffect } from "react";
import { marked } from "marked";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from "recharts";
import AlertCard from "./AlertCard";

const API = "https://netguard-ai-backend-qi2k.onrender.com";

// const SEVERITY_COLORS = {
//   critical: "#e24b4a",
//   high: "#ef9f27",
//   medium: "#378add",
//   low: "#1d9e75",
//   normal: "#888780",
// };

const PIE_COLORS = ["#e24b4a", "#ef9f27", "#378add", "#1d9e75"];

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [alertDetails, setAlertDetails] = useState(null);
  const [explanation, setExplanation] = useState("");
  const [explaining, setExplaining] = useState(false);

  // Load dashboard stats on mount and every 30s
  useEffect(() => {

    fetchStats();
    fetchHistory();

    const interval = setInterval(() => {

      fetchStats();
      fetchHistory();

    }, 30000);

    return () => clearInterval(interval);

  }, []);

  async function fetchStats() {
    try {
      const res = await fetch(`${API}/dashboard-stats`);
      const data = await res.json();
      setStats(data);
    } catch {
      console.error("Backend not reachable — using mock data");
      setStats(mockStats());
    } finally {
      setLoading(false);
    }
  }

  async function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;

    setUploading(true);
    setUploadResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API}/upload-log`, { method: "POST", body: formData });
      const data = await res.json();
      setUploadResult(data);
      await fetchStats();

      await fetchHistory();
    } catch {
      setUploadResult({ error: "Could not reach backend. Make sure uvicorn is running." });
    } finally {
      setUploading(false);
    }
  }

  // async function handleExplainAlert(alert) {
  //   setSelectedAlert(alert);
  //   setExplaining(true);
  //   setExplanation("");
  //   try {
  //     const res = await fetch(`${API}/explain-alert`, {
  //       method:  "POST",
  //       headers: { "Content-Type": "application/json" },
  //       body:    JSON.stringify({ features: alert }),
  //     });
  //     const data = await res.json();
  //     setExplanation(data.explanation);
  //   } catch {
  //     setExplanation("Backend not reachable. Please start uvicorn.");
  //   } finally {
  //     setExplaining(false);
  //   }
  // }
  async function handleExplainAlert(alert) {

    setSelectedAlert(alert);

    setExplaining(true);

    setExplanation("");

    setAlertDetails(null);

    try {

      const res = await fetch(
        `${API}/alert/${alert.id}`
      );

      const data = await res.json();

      setAlertDetails(data);

      setExplanation(
        data.explanation
      );

    } catch {

      setExplanation(
        "Backend not reachable."
      );

    } finally {

      setExplaining(false);

    }
  }


  async function fetchHistory() {
    try {

      const res = await fetch(
        `${API}/history`
      );

      const data = await res.json();

      setHistory(data);

    } catch (err) {

      console.error(
        "History load failed",
        err
      );
    }
  }

  if (loading) return <div className="loading">Loading dashboard...</div>;

  return (
    <div className="dashboard">

      {/* ── Stat Cards ── */}
      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Packets Today</div>
          <div className="stat-value">{stats.total_packets_today?.toLocaleString()}</div>
        </div>
        <div className="stat-card danger">
          <div className="stat-label">Threats Detected</div>
          <div className="stat-value">{stats.threats_detected}</div>
        </div>
        <div className="stat-card warning">
          <div className="stat-label">Blocked IPs</div>
          <div className="stat-value">{stats.blocked_ips}</div>
        </div>
        <div className="stat-card success">
          <div className="stat-label">Network Health</div>
          <div className="stat-value">{stats.network_health}%</div>
        </div>
      </div>

      {/* ── Charts Row ── */}
      <div className="charts-row">
        <div className="chart-card">
          <h3>Live Traffic (packets/sec)</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={stats.traffic_history}>
              <XAxis dataKey="time" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Line
                type="monotone"
                dataKey="packets"
                stroke="#378add"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Attack Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={stats.attack_distribution}
                cx="50%"
                cy="50%"
                outerRadius={70}
                dataKey="value"
                label={({ name, value }) => `${name} ${value}%`}
                labelLine={false}
              >
                {stats.attack_distribution.map((_, i) => (
                  <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Recent Alerts ── */}
      <div className="section">
        <h3>Recent Alerts</h3>
        <div className="alerts-list">
          {stats.recent_alerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              onExplain={() => handleExplainAlert(alert)}
            />
          ))}
        </div>
      </div>

      {/* ── Alert Explanation Modal ── */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>AI Explanation — {selectedAlert.type}</h3>
              <button className="modal-close" onClick={() => setSelectedAlert(null)}>✕</button>
            </div>
            {/* <div className="modal-body">
              {explaining
                ? <div className="thinking">🤖 Analyzing threat...</div>
                : <pre className="explanation-text">{explanation}</pre>
              }
            </div> */}
            <div className="modal-body">

              {explaining ? (

                <div className="thinking">
                  🤖 Analyzing threat...
                </div>

              ) : (

                <>
                  {alertDetails && (

                    <div className="alert-details">

                      <p>
                        <b>Severity:</b>{" "}
                        {alertDetails.severity}
                      </p>

                      <p>
                        <b>Score:</b>{" "}
                        {Number(
                          alertDetails.score
                        ).toFixed(6)}
                      </p>

                      {
                        alertDetails.top_features?.length > 0 &&
                        (
                          <>
                            <h4>
                              Top Contributing Features
                            </h4>

                            <ul>
                              {
                                alertDetails.top_features.map(
                                  (feature) => (
                                    <li key={feature}>
                                      {feature}
                                    </li>
                                  )
                                )
                              }
                            </ul>
                          </>
                        )
                      }

                    </div>

                  )}

                  {/* <pre className="explanation-text">
                    {explanation}
                  </pre> */}
                  <div
                    className="explanation-text"
                    dangerouslySetInnerHTML={{ __html: marked(explanation || "") }}
                  />

                </>

              )}

            </div>
          </div>
        </div>
      )}


      <div className="section">

        <h3>Detection History</h3>

        <div className="history-card">

          <table className="history-table">

            <thead>

              <tr>
                <th>Time</th>
                <th>Attack</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Source</th>
              </tr>

            </thead>

            <tbody>

              {history.map((item) => (

                <tr key={item.id}>

                  <td>
                    {new Date(
                      item.timestamp
                    ).toLocaleString()}
                  </td>

                  <td>
                    {item.attack_type}
                  </td>

                  <td>

                    <span
                      className={`severity-pill severity-${item.severity}`}
                    >
                      {item.severity}
                    </span>

                  </td>

                  <td>
                    {item.score?.toFixed(4)}
                  </td>

                  <td>
                    {item.source_ip}
                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>

      </div>


      {/* ── Log Upload ── */}
      <div className="section">
        {/* <h3>Upload Network Log (CSV)</h3> */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center"
          }}
        >

          <h3>
            Upload Network Log (CSV)
          </h3>

          <button
            className="download-btn"
            onClick={() =>
              window.open(
                `${API}/download-report`,
                "_blank"
              )
            }
          >
            📄 Download Report
          </button>

        </div>
        <div className="upload-area">
          <label className="upload-label">
            <input
              type="file"
              accept=".csv"
              onChange={handleFileUpload}
              style={{ display: "none" }}
            />
            <span className="upload-icon">📂</span>
            <span>{uploading ? "Analyzing..." : "Click to upload CSV log file"}</span>
          </label>
        </div>

        {uploadResult && !uploadResult.error && (
          <div className="upload-result">
            {/* <div className="result-summary">{uploadResult.summary}</div> */}
            <div
              className="result-summary"
              dangerouslySetInnerHTML={{ __html: marked(uploadResult.summary || "") }}
            />
            <div className="result-stats">
              <span>Total: <b>{uploadResult.total_analyzed}</b></span>
              <span className="danger-text">Anomalies: <b>{uploadResult.anomalies_found}</b></span>
              <span className="success-text">Normal: <b>{uploadResult.normal_count}</b></span>
            </div>
            {uploadResult.anomalies?.slice(0, 5).map((a, i) => (
              <div key={i} className={`mini-alert severity-${a.severity}`}>
                ⚠ {a.attack_type} — score: {a.score?.toFixed(4)} — {a.severity}
              </div>
            ))}
          </div>
        )}

        {uploadResult?.error && (
          <div className="error-box">{uploadResult.error}</div>
        )}
      </div>
    </div>
  );
}

// ── Mock data so UI renders without backend ───────────────────────────────────
function mockStats() {
  return {
    total_packets_today: 134200,
    threats_detected: 14,
    blocked_ips: 7,
    network_health: 81,
    traffic_history: Array.from({ length: 20 }, (_, i) => ({
      time: `T-${20 - i}`,
      packets: 900 + Math.floor(Math.random() * 400) + (i > 13 && i < 17 ? 1200 : 0),
    })),
    recent_alerts: [
      { id: 1, type: "SYN Flood (DDoS)", severity: "critical", ip: "192.168.1.45", time: "2 min ago", score: 0.312 },
      { id: 2, type: "Port Scan", severity: "high", ip: "10.0.0.87", time: "5 min ago", score: 0.187 },
      { id: 3, type: "Brute Force Attack", severity: "medium", ip: "172.16.0.12", time: "11 min ago", score: 0.094 },
    ],
    attack_distribution: [
      { name: "DDoS", value: 35 },
      { name: "Port Scan", value: 28 },
      { name: "Brute Force", value: 20 },
      { name: "Other", value: 17 },
    ],
  };
}