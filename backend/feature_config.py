"""
Feature Configuration — NetGuard AI
This module defines the Universal 17-Feature Architecture used across all AI models.
It strips out Kaggle dataset inconsistencies and ensures all models receive the exact
same mathematical dimensions.
"""

import re

def normalize_feature(f_name: str) -> str:
    """Removes all spaces, underscores, and special chars, and lowercases the name."""
    return re.sub(r'[^a-zA-Z0-9]', '', str(f_name)).lower()

# The 17 core features selected for maximum real-time predictability without relying on 
# brittle payload size features that break across different architectures.
FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
    "Idle Mean",
    "Active Max",
    "Idle Max"
]

NORMALIZED_FEATURES = [normalize_feature(f) for f in FEATURES]