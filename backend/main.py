"""
FastAPI Backend — NetGuard AI
All API endpoints consumed by the React frontend.
Run with: uvicorn main:app --reload
Docs at:  http://localhost:8000/docs
"""

import io

import numpy as np
import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from typing import Optional
from report_generator import generate_report
from fastapi.responses import FileResponse
from database import init_db
from database import get_alert_history
from rag_pipeline import query_rag
from anomaly_detector import detect_anomaly, analyze_log_file, load_or_train_model
from llm_engine import explain_anomaly, chat, summarize_log_analysis

load_dotenv()
# Stores latest detected anomalies from uploads
LATEST_ALERTS = []
LATEST_REPORT_DATA = {}
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





# ── Health check ─────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "NetGuard AI is running", "version": "1.0.0"}


@app.get("/health")
def health():
    return {"status": "ok"}


# ── Dashboard stats ───────────────────────────────────────────────────────────

@app.get("/dashboard-stats")
def dashboard_stats():
    """
    Returns dashboard statistics based on real detected alerts.
    """

    traffic_history = []

    if LATEST_REPORT_DATA.get("traffic_history"):

        traffic_history = LATEST_REPORT_DATA["traffic_history"]

    else:

        traffic_history = [
            {
                "time": str(i),
                "packets": 0
            }
            for i in range(1, 21)
        ]

    # -----------------------------
    # Real Alerts
    # -----------------------------

    recent_alerts = []

    for i, alert in enumerate(LATEST_ALERTS):

        recent_alerts.append({
            "id": i + 1,
            "type": alert["attack_type"],
            "severity": alert["severity"],
            "ip": f"Port {alert['raw'].get(' Destination Port', 'Unknown')}",
            "time": "Latest Upload",
            "score": round(alert["score"],6),
            "top_features": alert.get("top_features", [])
        })

    # -----------------------------
    # Dynamic Attack Distribution
    # -----------------------------

    attack_counts = {}

    for alert in LATEST_ALERTS:

        attack = alert["attack_type"]

        attack_counts[attack] = (
            attack_counts.get(attack, 0) + 1
        )

    attack_distribution = []

    for attack, count in attack_counts.items():

        attack_distribution.append({
            "name": attack,
            "value": count
        })

    # -----------------------------
    # Dynamic Network Health
    # -----------------------------

    network_health = max(
        0,
        100 - len(LATEST_ALERTS) * 5
    )

    return {
            "total_packets_today":
    LATEST_REPORT_DATA.get(
        "total_packets",
        0
    ),

        "threats_detected": len(LATEST_ALERTS),

        "blocked_ips": min(len(LATEST_ALERTS), 10),

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

    # Cap at 100 rows for speed in demo
    df = df.head(100).fillna(0)

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
    total_packets = 0

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

        total_packets += packets

        traffic_history.append({
            "time": f"Flow-{i+1}",
            "packets": int(packets)
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
    "total_analyzed": len(results),
    "anomalies_found": len(anomalies),
    "normal_count": len(normal),
    "summary": summary,
    "anomalies": anomalies[:20]
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





#Alert 
@app.get("/alert/{alert_id}")
def get_alert(alert_id: int):

    if alert_id < 1 or alert_id > len(LATEST_ALERTS):
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    alert = LATEST_ALERTS[alert_id - 1]

    explanation = explain_anomaly(
        alert,
        alert["raw"]
    )

    return {
        "id": alert_id,
        "attack_type": alert["attack_type"],
        "severity": alert["severity"],
        "score": round(alert["score"], 6),
        "top_features": alert.get("top_features", []),
        "explanation": explanation,
        "raw": alert["raw"]
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


@app.on_event("startup")
async def startup_event():

    print("[Startup] Initializing database...")
    init_db()

    print("[Startup] Loading anomaly model...")
    load_or_train_model()

    print("[Startup] Ready.")

@app.get("/history")
def history():

    return get_alert_history()