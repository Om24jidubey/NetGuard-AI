# 🛡️ NetGuard AI — AI-Powered Network Threat Detection Platform

<div align="center">

![NetGuard AI](https://img.shields.io/badge/NetGuard-AI-blue?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-LLM-FF6B35?style=for-the-badge)

**NetGuard AI** detects network intrusions using an Autoencoder neural network, explains threats using an LLM (Groq + RAG), and presents everything on a live React dashboard — helping network admins understand and respond to attacks instantly.

[Features](#-features) • [Architecture](#-architecture) • [ML Pipeline](#-ml-pipeline) • [Tech Stack](#-tech-stack) • [Setup](#-setup) • [API Reference](#-api-reference)

</div>

---

## 🚨 The Problem It Solves

Traditional network monitoring tools generate hundreds of raw alerts with no context — admins have to manually decode logs, cross-reference attack databases, and figure out what to do. This takes time, and in cybersecurity, time is everything.

**NetGuard AI** bridges this gap by:
- **Detecting anomalies** in network traffic using unsupervised ML (no labeled attack data needed)
- **Classifying attack types** (DDoS, Port Scan, SYN Flood, Brute Force, etc.)
- **Explaining threats in plain English** using an LLM + RAG pipeline
- **Providing an interactive chatbot** to ask security questions conversationally
- **Generating downloadable PDF reports** for audits and documentation

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Anomaly Detection** | Autoencoder neural network trained on normal traffic — flags deviations |
| 🎯 **Attack Classification** | Rule-based classifier identifies DDoS, SYN Flood, Port Scan, and more |
| 🤖 **LLM Threat Explainer** | Groq (LLaMA 3.1) explains every alert with remediation steps |
| 📚 **RAG Security Engine** | ChromaDB retrieves relevant security docs to ground LLM responses |
| 💬 **Security Chatbot** | Ask anything — "What is ARP Spoofing?" — and get expert answers |
| 📊 **Live Dashboard** | Real-time charts: traffic graph, attack distribution, alert history |
| 📄 **PDF Report Generator** | Download a full security report with one click |
| 🗄️ **Alert History** | All alerts stored in SQLite, queryable anytime |
| ⚡ **Severity Scoring** | Every anomaly scored as Low / Medium / High / Critical |

---

## 🏗️ Architecture

```
Network Traffic CSV (CICIDS2017 format)
           │
           ▼
    ┌─────────────────┐
    │  FastAPI Backend │  ← REST API + Business Logic
    └─────────────────┘
           │
    ┌──────┴──────────────────────────┐
    │                                 │
    ▼                                 ▼
┌─────────────────┐         ┌─────────────────────┐
│ Autoencoder ML  │         │   Groq LLM Engine   │
│ (Anomaly Det.)  │         │  (LLaMA 3.1-8B)     │
└────────┬────────┘         └──────────┬──────────┘
         │                             │
         ▼                             ▼
┌─────────────────┐         ┌─────────────────────┐
│Attack Classifier│         │  ChromaDB RAG Store │
│(Rule-Based)     │         │  (Security Docs)    │
└────────┬────────┘         └──────────┬──────────┘
         │                             │
         └──────────────┬──────────────┘
                        │
                        ▼
               ┌─────────────────┐
               │  SQLite Alerts  │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │  React Dashboard│
               │  + Recharts     │
               └─────────────────┘
```

---

## 🧠 ML Pipeline

This is the core of NetGuard AI. Here's exactly how it works:

### Why an Autoencoder?

Most intrusion detection systems need **labeled attack data** to train on — expensive, incomplete, and useless against new attack types.

An **Autoencoder** takes a different approach:
- Trained **only on normal (BENIGN) traffic**
- Learns to **reconstruct** normal network flows with very low error
- When an **attack** comes in → reconstruction error is high → **anomaly flagged**

This means NetGuard AI can detect **zero-day attacks it has never seen before**.

### Model Architecture

```
Input Layer    →  78 network features (MinMax scaled)
Encoder        →  Linear(78→64) → ReLU → Linear(64→32) → ReLU → Linear(32→8)
Latent Space   →  8 dimensions (compressed representation of normal traffic)
Decoder        →  Linear(8→32) → ReLU → Linear(32→64) → ReLU → Linear(64→78)
Output Layer   →  Reconstructed traffic features
```

### Anomaly Scoring

```python
reconstruction_error = MSE(original, reconstructed)

# Severity Thresholds
if error < threshold:              → Normal
elif error < threshold * 2:        → Low
elif error < threshold * 4:        → Medium  
elif error < threshold * 8:        → High
else:                              → Critical
```

### Top Feature Detection

For each anomaly, NetGuard identifies **which features caused the alert** (e.g., `Flow Packets/s`, `SYN Flag Count`) — giving admins precise forensic insight.

### Dataset

Trained on **CICIDS2017** (Canadian Institute for Cybersecurity Intrusion Detection dataset):
- Normal traffic: `BENIGN`
- Attack traffic: DDoS, Port Scan, Botnet, Brute Force, Web Attacks, DoS

---

## 🔬 Attack Classification

After anomaly detection, a **rule-based classifier** gives the attack a human-readable name:

| Condition | Detected Attack |
|---|---|
| `Flow Bytes/s > 1,000,000` | Volumetric DDoS |
| `Packet Rate > 5,000` | Packet Flood |
| `SYN Flag Count high` | SYN Flood |
| `Repeated port sweep pattern` | Port Scan |
| Other anomaly patterns | Suspicious Activity |

---

## 🤖 LLM + RAG Layer

Every detected threat is sent to **Groq (LLaMA 3.1-8B-instant)** with:
1. **Alert context**: attack type, severity score, top features
2. **RAG context**: relevant security documents retrieved from **ChromaDB**

The LLM returns a structured explanation:
- What the attack is
- Why it was flagged
- Why it's dangerous
- Recommended remediation steps

---

## 🛠️ Tech Stack

### Backend
| Technology | Purpose |
|---|---|
| **FastAPI** | REST API — async, auto-docs, Pydantic validation |
| **PyTorch** | Autoencoder neural network |
| **scikit-learn** | MinMaxScaler for feature normalization |
| **Groq API** | LLM inference (LLaMA 3.1-8B-instant) |
| **ChromaDB** | Vector DB for RAG security documents |
| **SQLite** | Alert history persistence |
| **ReportLab** | PDF report generation |
| **Pandas / NumPy** | Data preprocessing |

### Frontend
| Technology | Purpose |
|---|---|
| **React 18** | Dashboard UI |
| **Recharts** | Traffic graph + attack distribution pie chart |
| **Fetch API** | Backend communication |
| **CSS** | Custom styling |

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.10+
- Node.js 18+
- Groq API Key ([get one free](https://console.groq.com))

### Backend Setup

```bash
# Clone the repo
git clone https://github.com/yourusername/netguard-ai.git
cd netguard-ai/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Add your Groq API key
export GROQ_API_KEY="your_groq_api_key_here"

# Start the backend
uvicorn main:app --reload --port 8000
```

### Frontend Setup

```bash
cd ../frontend

# Install dependencies
npm install

# Start the frontend
npm start
```

Visit `http://localhost:3000` — the dashboard is live.

### Training the Model (Optional)

```bash
cd backend/ml

# Download CICIDS2017 dataset and place CSV in /data
python train_autoencoder.py

# Model saved to: models/autoencoder.pth
# Scaler saved to: models/scaler.pkl
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check |
| `GET` | `/dashboard-stats` | Packets, threats, health score |
| `POST` | `/upload-log` | Upload network traffic CSV |
| `POST` | `/analyze` | Run anomaly detection on uploaded log |
| `POST` | `/chat` | Ask the security chatbot a question |
| `GET` | `/history` | Get all stored alerts |
| `GET` | `/alert/{id}` | Get details + LLM explanation for one alert |
| `GET` | `/download-report` | Download PDF security report |

### Example: Upload & Analyze

```bash
# Upload a log file
curl -X POST http://localhost:8000/upload-log \
  -F "file=@network_traffic.csv"

# Analyze uploaded log
curl -X POST http://localhost:8000/analyze
```

### Example: Chat

```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is a SYN Flood attack and how do I stop it?"}'
```

---

## 📊 Dashboard Overview

The React dashboard provides:

- **📦 Packets Today** — total flows analyzed from the uploaded log
- **🚨 Threats Detected** — count of anomalies flagged in the latest analysis
- **💚 Network Health Score** — `100 - (anomalies × 5)` — at-a-glance health metric
- **📈 Traffic Graph** — packet volume over time (from uploaded log)
- **🥧 Attack Distribution** — pie chart of detected attack types
- **📋 Alert Table** — all alerts with severity badges, source IPs, and "Explain" button
- **💬 Chatbot Panel** — RAG-powered security Q&A

---

## ⚠️ Known Limitations

1. **Dataset-specific** — trained on CICIDS2017; may need retraining for different network environments
2. **Offline analysis** — currently processes uploaded CSV logs; real-time packet capture not yet implemented
3. **Heuristic classifier** — attack classification uses rules; could be upgraded to a supervised classifier
4. **SQLite** — suitable for development; not ideal for high-volume production use

---

## 🔮 Roadmap

- [ ] Real-time packet capture (libpcap / Scapy)
- [ ] Kafka streaming for live traffic analysis
- [ ] Supervised attack classifier (trained on labeled CICIDS2017 data)
- [ ] Automated model retraining pipeline
- [ ] Threat intelligence feed integration
- [ ] SIEM (Splunk / Elastic) integration
- [ ] Docker Compose deployment
- [ ] Cloud deployment (AWS / GCP)

---

## 📁 Project Structure

```
netguard-ai/
├── backend/
│   ├── main.py                  # FastAPI app & all endpoints
│   ├── ml/
│   │   ├── autoencoder.py       # PyTorch model definition
│   │   ├── train.py             # Training script
│   │   ├── inference.py         # Anomaly detection logic
│   │   └── classifier.py        # Rule-based attack classifier
│   ├── rag/
│   │   ├── chroma_store.py      # ChromaDB setup & retrieval
│   │   └── security_docs/       # Knowledge base documents
│   ├── db/
│   │   └── database.py          # SQLite alert storage
│   ├── reports/
│   │   └── generator.py         # ReportLab PDF generator
│   ├── models/
│   │   ├── autoencoder.pth      # Trained model weights
│   │   └── scaler.pkl           # Fitted MinMaxScaler
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Main dashboard component
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── AlertTable.jsx
│   │   │   ├── TrafficGraph.jsx
│   │   │   ├── AttackPieChart.jsx
│   │   │   └── Chatbot.jsx
│   │   └── index.css
│   └── package.json
├── data/
│   └── sample_traffic.csv       # Sample test data
└── README.md
```

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/real-time-capture`
3. Commit your changes: `git commit -m 'Add real-time packet capture'`
4. Push and open a PR

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with 🛡️ to make networks safer**

*If this project helped you, please give it a ⭐*

</div>
