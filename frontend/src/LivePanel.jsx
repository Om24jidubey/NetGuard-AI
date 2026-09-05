/**
 * Live Capture Dashboard — NetGuard AI
 * This component manages the real-time WebSocket connection to the backend,
 * dynamically rendering incoming packets into a live feed, updating statistics,
 * and handling UI interactions for mitigating threats or injecting simulated attacks.
 */
import React, { useState, useEffect, useRef } from "react";
import { marked } from "marked";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

// Dynamically use relative paths for production on Hugging Face Spaces
const API = process.env.REACT_APP_API_URL || "";
const WS_URL = process.env.REACT_APP_WS_URL || (window.location.protocol === "https:" ? `wss://${window.location.host}/ws/live` : `ws://${window.location.host || "localhost:8000"}/ws/live`);

export default function LivePanel({ setIsLive }) {
  const [capturing, setCapturing] = useState(false);
  const [logs, setLogs] = useState([]);
  const [isAttacking, setIsAttacking] = useState(false);

  useEffect(() => {
    if (setIsLive) setIsLive(capturing);
  }, [capturing, setIsLive]);

  const [stats, setStats] = useState({
    packets: 0,
    bytes: 0,
    threats: 0,
    health: 100,
  });
  const [mode, setMode] = useState("Offline");
  const [errorMsg, setErrorMsg] = useState("");
  const [chartData, setChartData] = useState([]);
  const [authModal, setAuthModal] = useState(false);
  
  // Explanation Modal state
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [explanation, setExplanation] = useState("");
  const [explaining, setExplaining] = useState(false);
  
  const ws = useRef(null);

  // Clean up WebSocket on unmount
  useEffect(() => {
    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  const handleStartClick = () => {
    setAuthModal(true);
  };

  const confirmStartCapturing = async (captureMode = "auto") => {
    setAuthModal(false);
    if (ws.current) return;
    setErrorMsg("");
    
    try {
      await fetch(`${API}/reset-session`, { method: "POST" });
    } catch (e) {
      console.error("Failed to reset session", e);
    }

    // Dynamically construct WebSocket URL using the pre-configured WS_URL
    const wsUrl = `${WS_URL}-capture?mode=${captureMode}`;
    console.log("[WS] Connecting to:", wsUrl);

    const socket = new WebSocket(wsUrl);
    ws.current = socket;
    setCapturing(true);
    setLogs([]);
    setStats({ packets: 0, bytes: 0, threats: 0, health: 100 });

    socket.onopen = () => {
      console.log("[WS] Connection established.");
    };

    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setMode(data.mode || "Live Capture");
      
      if (data.is_telemetry) {
          setChartData((prev) => {
             const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
             const noise = data.packets || 0;
             if (prev.length > 0 && prev[prev.length - 1].time === timeStr) {
                 const lastPoint = prev[prev.length - 1];
                 return [...prev.slice(0, -1), { ...lastPoint, packets: lastPoint.packets + noise }];
             } else {
                 return [...prev.slice(-149), { time: timeStr, packets: noise, anomaly: null }];
             }
          });
          setStats(s => ({ ...s, packets: data.global_packets ?? (s.packets + data.packets) }));
          return;
      }

      // Update logs list (limit to 50 items)
      setLogs((prevLogs) => [data, ...prevLogs.slice(0, 49)]);

      // Update Chart
      setChartData((prev) => {
        const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
        const flowPackets = data.packets || 0;
        
        if (prev.length > 0 && prev[prev.length - 1].time === timeStr) {
            // Aggregate packets within the same second
            const lastPoint = prev[prev.length - 1];
            const updatedPoint = {
                ...lastPoint,
                packets: lastPoint.packets + flowPackets,
                anomaly: data.is_anomaly ? ((lastPoint.anomaly || 0) + flowPackets) : lastPoint.anomaly
            };
            return [...prev.slice(0, prev.length - 1), updatedPoint];
        } else {
            // New second
            const newData = [...prev, { 
                time: timeStr, 
                packets: flowPackets, 
                anomaly: data.is_anomaly ? flowPackets : null 
            }];
            return newData.slice(-150);
        }
      });

      // Update accumulated stats directly from the backend's absolute truth
      setStats((prevStats) => {
        const packets = data.global_packets ?? (prevStats.packets + (data.packets || 1));
        const bytes = prevStats.bytes + (data.bytes || 64);
        const threats = data.global_threats ?? (prevStats.threats + (data.is_anomaly ? 1 : 0));
        const health = Math.max(0, 100 - threats * 5);
        return { packets, bytes, threats, health };
      });
    };

    socket.onclose = (event) => {
      console.log("[WS] Connection closed:", event.code, event.reason);
      ws.current = null;
      setCapturing(false);
      if (event.code !== 1000 && event.code !== 1001 && event.code !== 1005) {
        setErrorMsg(`Abnormal connection loss (Code ${event.code}). Target WebSocket URL: ${wsUrl}. Verify your backend is running locally on port 8000 and you restarted the npm server.`);
      }
    };

    socket.onerror = (error) => {
      console.error("[WS] WebSocket error:", error);
      // Detailed error logging
      setErrorMsg(`WebSocket handshake failed for ${wsUrl}. Verify port 8000 is open.`);
      socket.close();
    };
  };

  const stopCapturing = () => {
    if (ws.current) {
      ws.current.send("stop");
      ws.current.close();
    }
  };

  const handleClearSession = async () => {
    try {
      await fetch(`${API}/reset-session`, { method: "POST" });
      setLogs([]);
      setChartData([]);
      setStats({ packets: 0, bytes: 0, threats: 0, health: 100 });
      setMode("Live Capture");
    } catch (err) {
      console.error("Failed to clear session", err);
    }
  };

  const handleBlock = async (ip) => {
    try {
      await fetch(`${API}/block-ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      setLogs((prev) => {
        // Count how many anomalies we are mitigating from the live feed
        const removedAnomalies = prev.filter(log => log.source_ip === ip && log.is_anomaly).length;
        if (removedAnomalies > 0) {
          setStats(s => ({
            ...s,
            threats: Math.max(0, s.threats - removedAnomalies),
            health: Math.min(100, s.health + (removedAnomalies * 5))
          }));
        }
        return prev.filter(log => log.source_ip !== ip);
      });
    } catch (err) {
      console.error("Failed to block IP:", err);
      alert("Backend not reachable for blocking.");
    }
  };

  const handleExplain = async (flow) => {
    setSelectedFlow(flow);
    setExplaining(true);
    setExplanation("");

    try {
      const res = await fetch(`${API}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ features: flow.raw }),
      });

      if (!res.ok) throw new Error("Backend response error");
      const data = await res.json();
      setExplanation(data.explanation || "No explanation returned by the AI.");
    } catch (err) {
      console.error("Failed to explain flow:", err);
      setExplanation("Could not contact the NetGuard AI explanation engine. Verify backend logs.");
    } finally {
      setExplaining(false);
    }
  };

  return (
    <div className="live-panel">
      {/* ── Error Banner ── */}
      {errorMsg && (
        <div style={{
          background: "#ef444422",
          border: "1px solid #ef444444",
          borderRadius: "10px",
          color: "#ef4444",
          padding: "14px 18px",
          fontSize: "13px",
          lineHeight: "1.6",
          display: "flex",
          flexDirection: "column",
          gap: "4px"
        }}>
          <span style={{ fontWeight: "600", fontSize: "14px" }}>⚠️ WebSocket Connection Failed</span>
          <span>{errorMsg}</span>
        </div>
      )}

      {/* ── Action Bar ── */}
      <div className="live-action-bar">
        <div className="live-status-group">
          {capturing ? (
            <div 
              className="live-badge-recording"
              style={{
                background: mode.includes("Simulat") ? "rgba(245, 158, 11, 0.15)" : "rgba(16, 185, 129, 0.15)",
                color: mode.includes("Simulat") ? "#f59e0b" : "#10b981",
                border: mode.includes("Simulat") ? "1px solid rgba(245, 158, 11, 0.3)" : "1px solid rgba(16, 185, 129, 0.3)"
              }}
              title={mode.includes("Simulat") ? "Using simulated dataset because raw socket permissions are missing." : "Listening to real network interfaces."}
            >
              <span 
                className="live-dot-recording"
                style={{
                  background: mode.includes("Simulat") ? "#f59e0b" : "#10b981",
                  boxShadow: mode.includes("Simulat") ? "0 0 8px #f59e0b" : "0 0 8px #10b981"
                }}
              ></span>
              {mode.toUpperCase()} ACTIVE
            </div>
          ) : (
            <div className="live-badge-offline">
              <span className="live-dot-offline"></span>
              OFFLINE
            </div>
          )}
          <span className="live-help-text">
            {capturing 
              ? "Sniffing packets on local interfaces or streaming normal/threat datasets..." 
              : "Start monitoring to inspect real-time network flows and threats."}
          </span>
        </div>
        <div className="live-buttons">
          {!capturing ? (
            <button className="start-btn" onClick={handleStartClick}>
              ⚡ Start Live Capture
            </button>
          ) : (
            <>
              <button 
                className="start-btn" 
                style={{ 
                  background: isAttacking ? "#991b1b" : "#ef4444", 
                  border: isAttacking ? "1px solid #7f1d1d" : "1px solid #dc2626", 
                  marginRight: "10px" 
                }}
                onClick={async () => {
                  try {
                    if (isAttacking) {
                      await fetch(`${API}/stop-attack`, { method: "POST" });
                      setIsAttacking(false);
                    } else {
                      setIsAttacking(true);
                      await fetch(`${API}/simulate-attack`, { method: "POST" });
                      // Reset button after 20 seconds
                      setTimeout(() => setIsAttacking(false), 20000);
                    }
                  } catch (e) {
                    console.error(e);
                  }
                }}
                title="Toggle volumetric DDoS injection"
              >
                {isAttacking ? "🛑 Stop Threat" : "🔥 Inject Threat"}
              </button>
              <button className="stop-btn" onClick={stopCapturing}>
                🛑 Stop Capture
              </button>
            </>
          )}
          <button 
            className="download-btn" 
            style={{ background: "#444", border: "none", marginLeft: "10px" }}
            onClick={handleClearSession}
            disabled={capturing}
            title={capturing ? "Stop capture first to clear session" : "Clear all logs and graphs"}
          >
            🗑️ Clear Session
          </button>
        </div>
      </div>

      {/* ── Live Stats Grid ── */}
      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Sniffed Packets</div>
          <div className="stat-value">{stats.packets.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total Volume</div>
          <div className="stat-value">
            {stats.bytes > 1024 * 1024 * 1024
              ? (stats.bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB"
              : stats.bytes > 1024 * 1024
              ? (stats.bytes / (1024 * 1024)).toFixed(2) + " MB"
              : (stats.bytes / 1024).toFixed(2) + " KB"}
          </div>
        </div>
        <div className="stat-card danger">
          <div className="stat-label">Live Anomalies</div>
          <div className="stat-value">{stats.threats}</div>
        </div>
        <div className="stat-card success">
          <div className="stat-label">Dynamic Health Score</div>
          <div className="stat-value">{stats.health}%</div>
        </div>
      </div>

      {/* ── Live Graph ── */}
      <div className="section" style={{ marginTop: "20px" }}>
        <h3>Live Traffic Analysis</h3>
        <div className="chart-card">
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={chartData}>
              <XAxis dataKey="time" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Line type="monotone" dataKey="packets" stroke="#378add" strokeWidth={2} dot={false} name="Total Packets" />
              <Line type="step" dataKey="anomaly" stroke="#e24b4a" strokeWidth={3} dot={{ r: 4 }} name="Anomalous Packets" connectNulls={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Real-Time Logs ── */}
      <div className="section">
        <h3>Real-Time Network Activity Feed</h3>
        <div className="live-table-container">
          <table className="live-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Proto</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Anomaly Score</th>
                <th>Severity</th>
                <th>Attack Label</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan="10" className="no-data-cell">
                    {capturing ? "Waiting for network traffic..." : "Capture offline. Click Start above."}
                  </td>
                </tr>
              ) : (
                logs.map((log, idx) => (
                  <tr key={idx} className={log.is_anomaly ? "live-row-anomaly" : ""}>
                    <td>{log.timestamp}</td>
                    <td className="mono">{log.source_ip}:{log.source_port}</td>
                    <td className="mono">{log.dest_ip}:{log.dest_port}</td>
                    <td><span className="proto-tag">{log.protocol}</span></td>
                    <td>{log.packets}</td>
                    <td>{log.bytes}</td>
                    <td className="mono">{log.score.toFixed(5)}</td>
                    <td>
                      <span className={`severity-pill severity-${log.severity}`}>
                        {log.severity}
                      </span>
                    </td>
                    <td className={log.is_anomaly ? "danger-text text-bold" : ""}>
                      {log.attack_type}
                    </td>
                    <td>
                      {log.is_anomaly && (
                        <div style={{ display: "flex", gap: "5px" }}>
                          <button className="explain-btn-mini" onClick={() => handleExplain(log)}>
                            🤖 Explain
                          </button>
                          <button className="explain-btn-mini" style={{ background: "#ef4444", color: "#fff", border: "none" }} onClick={() => handleBlock(log.source_ip)}>
                            🚫 Block
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Threat Explanation Modal ── */}
      {selectedFlow && (
        <div className="modal-overlay" onClick={() => setSelectedFlow(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>AI Explanation — {selectedFlow.attack_type}</h3>
              <button className="modal-close" onClick={() => setSelectedFlow(null)}>✕</button>
            </div>
            <div className="modal-body">
              {explaining ? (
                <div className="thinking">🤖 Requesting threat model attribution and RAG docs...</div>
              ) : (
                <>
                  <div className="alert-details">
                    <p><b>Timestamp:</b> {selectedFlow.timestamp}</p>
                    <p><b>Source Address:</b> {selectedFlow.source_ip}:{selectedFlow.source_port}</p>
                    <p><b>Severity Rating:</b> <span className={`severity-pill severity-${selectedFlow.severity}`}>{selectedFlow.severity}</span></p>
                    <p><b>Reconstruction Loss:</b> {selectedFlow.score.toFixed(6)}</p>
                    {selectedFlow.top_features?.length > 0 && (
                      <>
                        <h4>Triggering Network Columns:</h4>
                        <ul>
                          {selectedFlow.top_features.map((f) => (
                            <li key={f} className="mono">{f}</li>
                          ))}
                        </ul>
                      </>
                    )}
                  </div>
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
      {/* ── Authorization Modal ── */}
      {authModal && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>OS Authorization Required</h3>
              <button className="modal-close" onClick={() => setAuthModal(false)}>✕</button>
            </div>
            <div className="modal-body" style={{ color: "#eee", fontSize: "14px", lineHeight: "1.6" }}>
              <p>
                To enable <strong>Live Packet Capturing</strong>, NetGuard AI requires temporary administrative access to place the server's network interfaces into promiscuous mode.
              </p>
              <div style={{ background: "#2a2a2a", padding: "12px", borderRadius: "5px", marginTop: "15px", borderLeft: "4px solid #ef9f27" }}>
                <strong>Security Notice:</strong> In this web dashboard environment, capturing is strictly authorized and limited to the host server infrastructure only.
              </div>
              <div style={{ marginTop: "20px", display: "flex", justifyContent: "flex-end", gap: "10px" }}>
                <button className="download-btn" style={{ background: "#444" }} onClick={() => setAuthModal(false)}>Cancel</button>
                <button className="download-btn" style={{ background: "#f59e0b", color: "#111", border: "none" }} onClick={() => confirmStartCapturing("simulate")}>Simulate Traffic</button>
                <button className="start-btn" onClick={() => confirmStartCapturing("auto")}>Authorize & Start</button>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
