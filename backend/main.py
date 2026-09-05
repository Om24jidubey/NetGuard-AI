"""
FastAPI Backend — NetGuard AI
This file is the core entry point for the backend server.
It handles all API requests from the React frontend, manages background sniffing threads,
and integrates with the database and AI models.

Run with: uvicorn main:app --reload
Docs at:  http://localhost:8000/docs
"""

# ==============================================================================
# 1. Imports & Environment Setup
# ==============================================================================
import os
import io
import asyncio
import threading
from typing import Optional

import numpy as np
import pandas as pd
import torch
from fastapi import FastAPI, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

from live_capture import LiveCaptureManager, BLOCKED_IPS
from report_generator import generate_report
from database import init_db, get_alert_history
from rag_pipeline import query_rag
from anomaly_detector import detect_anomaly, analyze_log_file, load_or_train_model
from llm_engine import explain_anomaly, chat, summarize_log_analysis

# Limit thread usage for PyTorch/Numpy to prevent CPU lockups during high traffic
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
torch.set_num_threads(1)
load_dotenv()
# Stores latest detected anomalies from uploads
LATEST_ALERTS = []
LATEST_REPORT_DATA = {}
# Stores a rolling window of recent packets for the Dashboard graph
LIVE_TRAFFIC_HISTORY = [{"time": str(i), "packets": 0} for i in range(1, 21)]
GLOBAL_TOTAL_PACKETS = 0
IS_CAPTURING = False

import threading
traffic_lock = threading.Lock()
# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="NetGuard AI",
    description="AI-Powered Network Threat Detection & Explanation System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response models ─────────────────────────────────────────────────
class ChatRequest(BaseModel):
    question: str
    history: Optional[list] = []


class ManualAnalyzeRequest(BaseModel):
    features: dict

class BlockIPRequest(BaseModel):
    ip: str





# ── Health check & Frontend Serving ───────────────────────────────────────────
from fastapi.staticfiles import StaticFiles

# We will mount the static frontend at the bottom of the file to prevent it from catching API routes
@app.get("/api/health")
def health_api():
    return {"status": "NetGuard AI API is running", "version": "1.0.0"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/reset-session")
def reset_session():
    global GLOBAL_TOTAL_PACKETS
    global LIVE_TRAFFIC_HISTORY
    global LATEST_REPORT_DATA
    global LATEST_ALERTS
    
    with traffic_lock:
        GLOBAL_TOTAL_PACKETS = 0
        LIVE_TRAFFIC_HISTORY.clear()
        LATEST_REPORT_DATA = {}
        LATEST_ALERTS = []
    
    import database
    from live_capture import BLOCKED_IPS
    
    database.GLOBAL_TOTAL_THREATS = 0
    database.GLOBAL_ATTACK_COUNTS.clear()
    BLOCKED_IPS.clear()
    database.clear_all_alerts()
    return {"status": "ok"}

@app.post("/clear-csv")
def clear_csv():
    global LATEST_REPORT_DATA
    global LATEST_ALERTS
    LATEST_REPORT_DATA = {}
    LATEST_ALERTS = []
    
    import database
    database.GLOBAL_TOTAL_THREATS = 0
    database.GLOBAL_ATTACK_COUNTS.clear()
    database.clear_all_alerts()

    return {"status": "ok"}
    
# ── Dashboard stats ───────────────────────────────────────────────────────────

@app.get("/blocked-ips")
def get_blocked_ips():
    from live_capture import BLOCKED_IPS
    return {"blocked_ips": list(BLOCKED_IPS)}

@app.post("/unblock-ip")
def unblock_ip(req: dict):
    ip = req.get("ip")
    from live_capture import BLOCKED_IPS
    if ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)
    return {"status": "ok"}

@app.post("/simulate-attack")
def simulate_attack():
    """Spawns a real background thread to inject a 10-second UDP flood."""
    from attack_tester import udp_flood_simulation
    import threading
    t = threading.Thread(target=udp_flood_simulation, args=(20,)) # Raised to 20 seconds
    t.daemon = True
    t.start()
    return {"status": "Injection started. Network traffic spiking."}

@app.post("/stop-attack")
def stop_attack():
    """Stops the background UDP flood thread."""
    from attack_tester import global_stop_event
    global_stop_event.set()
    return {"status": "Attack stopped."}

@app.get("/dashboard-stats")
def dashboard_stats():
    """
    Returns dashboard statistics based on real detected alerts.
    """
    history_db = get_alert_history()
    from live_capture import BLOCKED_IPS
    
    # Filter out blocked IPs from recent alerts feed
    history_db_unblocked = [a for a in history_db if str(a.get("source_ip", "")).split(':')[0] not in BLOCKED_IPS]
    recent_db = history_db_unblocked[:20]

    # Use the live traffic history if available, else fallback to CSV upload data or zeros
    if any(point["packets"] > 0 for point in LIVE_TRAFFIC_HISTORY):
        traffic_history = list(LIVE_TRAFFIC_HISTORY)
    else:
        traffic_history = LATEST_REPORT_DATA.get("traffic_history", [{"time": str(i), "packets": 0} for i in range(1, 21)])

    recent_alerts = []
    for alert in recent_db:
        recent_alerts.append({
            "id": alert["id"],
            "type": alert["attack_type"],
            "severity": alert["severity"],
            "ip": alert["source_ip"],
            "time": alert["timestamp"],
            "score": round(alert["score"], 6),
            "top_features": []
        })

    import database
    if database.GLOBAL_ATTACK_COUNTS:
        attack_distribution = [{"name": k, "value": v} for k, v in database.GLOBAL_ATTACK_COUNTS.items()]
    else:
        attack_counts = {}
        for alert in history_db:
            attack = alert["attack_type"]
            attack_counts[attack] = attack_counts.get(attack, 0) + 1
        attack_distribution = [{"name": k, "value": v} for k, v in attack_counts.items()]
    
    # Filter out blocked IPs to calculate *active* threats
    active_threats = [a for a in history_db if a["source_ip"].split(':')[0] not in BLOCKED_IPS]
    network_health = max(0, 100 - len(active_threats) * 5)

    import database
    return {
        "total_packets_today": LATEST_REPORT_DATA.get("total_packets", GLOBAL_TOTAL_PACKETS),
        "threats_detected": LATEST_REPORT_DATA.get("anomalies_found", database.GLOBAL_TOTAL_THREATS),
        "blocked_ips": len(BLOCKED_IPS),
        "network_health": network_health,
        "traffic_history": traffic_history,
        "recent_alerts": recent_alerts,
        "attack_distribution": attack_distribution
    }

# ── Upload & analyze a log file ───────────────────────────────────────────────
@app.post("/upload-log")
async def upload_log(file: UploadFile = File(...)):
    """
    Accept a CSV log file, run anomaly detection on every row,
    and return results + an LLM-generated executive summary.
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")

    contents = await file.read()
    try:
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {e}")

    from feature_config import normalize_feature
    df.columns = [normalize_feature(c) for c in df.columns]

    # For dashboard simulation, limit processing to a random 2000 rows to ensure instant response times
    total_rows_uploaded = len(df)
    import numpy as np
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df = df.fillna(0)
    
    if len(df) > 2000:
        df = df.sample(n=2000, random_state=42)
        
    rows_analyzed = len(df)
    results = analyze_log_file(df)
    global LATEST_ALERTS

    LATEST_ALERTS = [
        r for r in results
        if r["is_anomaly"]
    ][:20]
    from database import save_alert
    for alert in LATEST_ALERTS:

        raw = alert.get("raw", {})

        source_ip = (
            raw.get(" Source IP")
            or str(raw.get(" Destination Port", "Unknown"))
        )

        save_alert(
            attack_type=alert["attack_type"],
            severity=alert["severity"],
            score=alert["score"],
            source_ip=source_ip
        )

    # Generate executive summary
    try:
        summary = summarize_log_analysis(results)
    except Exception:
        num_anomalies = sum(1 for r in results if r["is_anomaly"])
        summary = f"Analyzed {len(results)} records. Found {num_anomalies} anomalies."

    anomalies = [r for r in results if r["is_anomaly"]]
    normal    = [r for r in results if not r["is_anomaly"]]
    
    # "Packets" in the context of CSV upload refers to the number of rows/flows analyzed
    total_packets = len(results)

    traffic_history = []

    for i, row in enumerate(results[:20]):

        raw = row["raw"]

        packets = (
            raw.get(
                " Total Fwd Packets",
                0
            )
            +
            raw.get(
                " Total Backward Packets",
                0
            )
        )

        traffic_history.append({
            "time": f"Flow-{i+1}",
            "packets": int(packets),
            "anomaly": int(packets) if row["is_anomaly"] else None
        })

    #extra
    global LATEST_REPORT_DATA

    attack_counts = {}

    for alert in anomalies:

        attack = alert["attack_type"]

        attack_counts[attack] = (
            attack_counts.get(attack, 0) + 1
        )

    LATEST_REPORT_DATA = {

    "total_packets": int(
        total_packets
    ),

    "traffic_history":
        traffic_history,

    "total_analyzed":
        len(results),

    "anomalies_found":
        len(anomalies),

    "network_health":
        max(
            0,
            100 - len(anomalies) * 5
        ),
       

    "attack_distribution": [
        {
            "name": k,
            "value": v
        }
        for k, v in attack_counts.items()
    ]
}
    
    return {
    "total_rows_uploaded": total_rows_uploaded,
    "total_analyzed": len(results),
    "anomalies_found": len(anomalies),
    "normal_count": len(normal),
    "summary": summary,
    "anomalies": anomalies[:20],
    "note": f"Only first {rows_analyzed} rows analyzed for demo performance."
}


# ── Analyze manually entered features ────────────────────────────────────────
@app.post("/analyze")
def analyze_manual(request: ManualAnalyzeRequest):
    """
    Analyze a single set of network traffic features.
    Returns anomaly result + LLM explanation.
    """
    result = detect_anomaly(request.features)

    explanation = ""
    if result["is_anomaly"]:
        try:
            explanation = explain_anomaly(result, request.features)
        except Exception as e:
            explanation = f"Anomaly detected: {result['attack_type']}. (LLM explanation unavailable: {e})"
    else:
        explanation = "Traffic appears normal. No anomalies detected."

    return {
        **result,
        "explanation": explanation
    }


# ── Explain a specific alert ──────────────────────────────────────────────────
# @app.post("/explain-alert")
# def explain_alert(request: ManualAnalyzeRequest):
#     """
#     Given alert data (from dashboard), return a full LLM explanation.
#     """
#     features    = request.features
#     attack_type = features.get("attack_type", "Unknown Anomaly")
#     severity    = features.get("severity", "medium")
#     score       = float(features.get("score", 0.1))

#     anomaly_result = {
#         "is_anomaly": True,
#         "attack_type": attack_type,
#         "severity": severity,
#         "score": score
#     }

#     try:
#         explanation = explain_anomaly(anomaly_result, features)
#     except Exception as e:
#         # Fallback to RAG-only if LLM fails
#         context = query_rag(f"What is {attack_type} and how to fix it?")
#         explanation = f"Based on documentation:\n\n{context[:600]}"

#     return {"explanation": explanation, "attack_type": attack_type}


# ── AI Chat endpoint ──────────────────────────────────────────────────────────
@app.post("/chat")
def chat_endpoint(request: ChatRequest):
    """
    Free-form security Q&A with conversation history.
    Frontend sends full conversation history each time.
    """
    if not request.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    try:
        answer = chat(request.question, request.history)
    except Exception as e:
        # Fallback: answer from RAG only if LLM unavailable
        context = query_rag(request.question)
        answer = f"Based on security documentation:\n\n{context[:800]}"

    return {"answer": answer, "question": request.question}


# ── RAG-only search ───────────────────────────────────────────────────────────
@app.get("/search-docs")
def search_docs(q: str):
    """Search the security knowledge base directly (no LLM)."""
    if not q:
        raise HTTPException(status_code=400, detail="Query parameter 'q' is required.")
    context = query_rag(q, k=3)
    return {"query": q, "results": context}


@app.post("/block-ip")
def block_ip(request: BlockIPRequest):
    """Adds an IP to the global blocklist."""
    BLOCKED_IPS.add(request.ip)
    print(f"[Firewall] Blocked IP: {request.ip}")
    return {"status": "success", "blocked_ip": request.ip}





@app.get("/alert/{alert_id}")
def get_alert(alert_id: int):
    from database import SessionLocal, Alert
    db = SessionLocal()
    try:
        db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not db_alert:
            raise HTTPException(status_code=404, detail="Alert not found in database")
        
        # Construct dict for explain_anomaly
        alert_dict = {
            "attack_type": db_alert.attack_type,
            "severity": db_alert.severity,
            "score": db_alert.score,
            "top_features": [],
            "raw": {}
        }
    finally:
        db.close()

    # Generate explanation from LLM using the database alert details
    explanation = explain_anomaly(alert_dict, {})

    return {
        "id": alert_id,
        "attack_type": alert_dict["attack_type"],
        "severity": alert_dict["severity"],
        "score": round(alert_dict["score"], 6),
        "top_features": [],
        "explanation": explanation,
        "raw": {}
    }



#download report
@app.get("/download-report")
def download_report():

    if not LATEST_REPORT_DATA:

        raise HTTPException(
            status_code=404,
            detail="No report available"
        )

    report_path = "security_report.pdf"

    generate_report(
        LATEST_REPORT_DATA,
        report_path
    )

    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename="NetGuard_Report.pdf"
    )


@app.websocket("/ws/live-capture")
async def websocket_live_capture(websocket: WebSocket, mode: str = "auto"):
    global IS_CAPTURING
    IS_CAPTURING = True
    await websocket.accept()
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue()

    def on_flow_detected(flow_data):
        import time
        time_str = time.strftime("%H:%M:%S")
        added_packets = flow_data.get("packets", 0)
        
        with traffic_lock:
            global GLOBAL_TOTAL_PACKETS
            global LIVE_TRAFFIC_HISTORY
            GLOBAL_TOTAL_PACKETS += added_packets
            
            import database
            flow_data["global_packets"] = GLOBAL_TOTAL_PACKETS
            flow_data["global_threats"] = database.GLOBAL_TOTAL_THREATS

            if LIVE_TRAFFIC_HISTORY and LIVE_TRAFFIC_HISTORY[-1]["time"] == time_str:
                LIVE_TRAFFIC_HISTORY[-1]["packets"] += added_packets
            else:
                LIVE_TRAFFIC_HISTORY.append({"time": time_str, "packets": added_packets})
                if len(LIVE_TRAFFIC_HISTORY) > 100:
                    LIVE_TRAFFIC_HISTORY.pop(0)

        loop.call_soon_threadsafe(queue.put_nowait, flow_data)

    manager = LiveCaptureManager(callback=on_flow_detected, mode=mode)
    manager.start()

    async def telemetry_worker():
        import random
        try:
            while True:
                await asyncio.sleep(1)
                baseline = random.randint(15, 45)
                with traffic_lock:
                    global GLOBAL_TOTAL_PACKETS
                    GLOBAL_TOTAL_PACKETS += baseline
                    
                    telemetry = {
                        "is_telemetry": True,
                        "packets": baseline,
                        "global_packets": GLOBAL_TOTAL_PACKETS,
                        "mode": "Simulated Live" if manager.is_simulated else "Live Sniffing"
                    }
                await queue.put(telemetry)
        except asyncio.CancelledError:
            pass


    async def send_worker():
        try:
            while True:
                flow_data = await queue.get()
                await websocket.send_json(flow_data)
                queue.task_done()
        except Exception as e:
            print(f"[WS] Send worker exception: {e}")

    send_task = asyncio.create_task(send_worker())
    telemetry_task = asyncio.create_task(telemetry_worker())

    try:
        while True:
            data = await websocket.receive_text()
            if data == "stop":
                print("[WS] Stop command received from client.")
                break
    except WebSocketDisconnect:
        print("[WS] Client disconnected.")
    except Exception as e:
        print(f"[WS] Connection error: {e}")
    finally:
        IS_CAPTURING = False
        manager.stop()
        send_task.cancel()
        telemetry_task.cancel()
        try:
            await send_task
            await telemetry_task
        except asyncio.CancelledError:
            pass


async def traffic_ticker():
    import time
    import random
    while True:
        await asyncio.sleep(1)
        if not IS_CAPTURING:
            continue
            
        global LIVE_TRAFFIC_HISTORY
        global GLOBAL_TOTAL_PACKETS
        time_str = time.strftime("%H:%M:%S")
        
        with traffic_lock:
            if not LIVE_TRAFFIC_HISTORY or LIVE_TRAFFIC_HISTORY[-1]["time"] != time_str:
                baseline = random.randint(10, 20)
                GLOBAL_TOTAL_PACKETS += baseline
                LIVE_TRAFFIC_HISTORY.append({"time": time_str, "packets": baseline})
                if len(LIVE_TRAFFIC_HISTORY) > 100:
                    LIVE_TRAFFIC_HISTORY.pop(0)

@app.on_event("startup")
async def startup_event():

    print("[Startup] Initializing database...")
    init_db()
    
    # Wipe the persistent DB on startup so it stays in perfect sync 
    # with the in-memory global RAM packet counters that reset to 0
    import database
    database.clear_all_alerts()

    print("[Startup] Loading anomaly model...")
    load_or_train_model()

    # Start the continuous 1-second live ticker
    asyncio.create_task(traffic_ticker())

    print("[Startup] Ready.")

@app.get("/history")
def history():

    return get_alert_history()


# ── Static Frontend Serving (Must be at the very bottom) ──────────────────────
FRONTEND_BUILD_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "build")

# If the build directory exists, mount it so FastAPI serves the React app
if os.path.isdir(FRONTEND_BUILD_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_BUILD_DIR, html=True), name="static")
else:
    print(f"[Warning] Frontend build directory not found at {FRONTEND_BUILD_DIR}. UI will not be served.")