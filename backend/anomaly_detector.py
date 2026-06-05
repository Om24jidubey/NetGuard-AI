import os
import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from pathlib import Path
from feature_config import FEATURES

MODEL_PATH = "../models/autoencoder.pt"
SCALER_PATH = "../models/scaler.pkl"

THRESHOLD = 0.002

# ---------------------------
# Autoencoder Architecture
# ---------------------------

LATENT_DIM = 8


class Autoencoder(nn.Module):

    def __init__(self, input_dim):
        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, LATENT_DIM)
        )

        self.decoder = nn.Sequential(
            nn.Linear(LATENT_DIM, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z)


# ---------------------------
# Globals
# ---------------------------

_model = None
_scaler = None
_loaded = False


def load_or_train_model():
    global _model, _scaler, _loaded

    if _loaded:
        return

    print("[Detector] Loading trained model...")

    _scaler = joblib.load(SCALER_PATH)

    _model = Autoencoder(len(FEATURES))

    _model.load_state_dict(
        torch.load(MODEL_PATH, map_location="cpu")
    )

    _model.eval()

    _loaded = True

    print("[Detector] Ready.")


def detect_anomaly(raw_features: dict):

    global _model, _scaler

    if not _loaded:
        load_or_train_model()

    values = []

    for feature in FEATURES:
        values.append(
            float(raw_features.get(feature, 0))
        )

    X = np.array([values])

    try:
        X_scaled = _scaler.transform(X)
    except Exception:
        return {
            "is_anomaly": False,
            "score": 0,
            "severity": "normal",
            "attack_type": "Invalid Input",
            "top_features": []
        }

    tensor = torch.FloatTensor(X_scaled)

    with torch.no_grad():

        reconstructed = _model(tensor)

        feature_errors = torch.abs(
            reconstructed - tensor
        ).squeeze().numpy()

        error = np.mean(
            feature_errors ** 2
        )

        top_indices = np.argsort(
            feature_errors
        )[::-1][:3]

        top_features = [
            FEATURES[i]
            for i in top_indices
        ]

    is_anomaly = bool(error > THRESHOLD)

    return {
    "is_anomaly": bool(is_anomaly),

    "score": float(round(error, 6)),

    "severity": str(_severity(error)),

    "attack_type": str(
        _guess_attack_type(raw_features)
        if is_anomaly
        else "Normal Traffic"
    ),

    "top_features": [
        str(x) for x in (
            top_features if is_anomaly else []
        )
    ]
}


def analyze_log_file(df: pd.DataFrame):

    results = []

    for _, row in df.iterrows():

        result = detect_anomaly(
            row.to_dict()
        )

        result["raw"] = row.to_dict()

        results.append(result)

    return results


def _severity(error):

    if error < THRESHOLD:
        return "normal"

    elif error < THRESHOLD * 2:
        return "low"

    elif error < THRESHOLD * 4:
        return "medium"

    elif error < THRESHOLD * 8:
        return "high"

    return "critical"


def _guess_attack_type(features):

    flow_rate = float(
        features.get("Flow Bytes/s", 0)
    )

    packet_rate = float(
        features.get(" Flow Packets/s", 0)
    )

    packets = float(
        features.get(" Total Fwd Packets", 0)
    )

    syn = float(
        features.get(" SYN Flag Count", 0)
    )

    avg_packet = float(
        features.get(" Average Packet Size", 0)
    )

    duration = float(
        features.get(" Flow Duration", 0)
    )

    # -----------------------------
    # DDoS
    # -----------------------------

    if flow_rate > 1_000_000:

        return "Volumetric DDoS"

    if packet_rate > 5_000:

        return "Packet Flood Attack"

    if syn > 5 and packet_rate > 1_000:

        return "SYN Flood (DDoS)"

    # -----------------------------
    # Port Scan
    # -----------------------------

    if (
        packets > 100
        and avg_packet < 100
        and duration < 100000
    ):
        return "Port Scan"

    # -----------------------------
    # Data Exfiltration
    # -----------------------------

    if (
        flow_rate > 500000
        and avg_packet > 1000
    ):
        return "Possible Data Exfiltration"

    # -----------------------------
    # Generic anomaly
    # -----------------------------

    return "Suspicious Network Activity"