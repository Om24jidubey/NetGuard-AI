import os
import sys
import pandas as pd
import numpy as np
import torch
import joblib
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
sys.path.append(str(backend_dir))

from anomaly_detector import Autoencoder, load_or_train_model, detect_anomaly
from feature_config import FEATURES

DATA_DIR = backend_dir.parent / "data" / "cicids2017"

def evaluate():
    monday_path = DATA_DIR / "monday_subset.csv"
    ddos_path = DATA_DIR / "ddos_subset.csv"
    
    if not monday_path.exists() or not ddos_path.exists():
        print(f"[EVAL] Error: Datasets not found in {DATA_DIR}")
        sys.exit(1)
        
    print("[EVAL] Loading datasets...")
    # Load normal samples (Monday)
    df_normal = pd.read_csv(monday_path).fillna(0)
    # Load attack samples (DDoS)
    df_attack = pd.read_csv(ddos_path).fillna(0)
    
    print(f"[EVAL] Normal rows: {len(df_normal)}, Attack rows: {len(df_attack)}")
    
    # Sample for faster evaluation
    df_normal_sampled = df_normal.sample(min(5000, len(df_normal)), random_state=42)
    df_attack_sampled = df_attack.sample(min(5000, len(df_attack)), random_state=42)
    
    print("[EVAL] Running anomaly detection on Normal traffic...")
    normal_results = []
    for _, row in df_normal_sampled.iterrows():
        res = detect_anomaly(row.to_dict())
        normal_results.append(res)
        
    print("[EVAL] Running anomaly detection on Attack traffic...")
    attack_results = []
    for _, row in df_attack_sampled.iterrows():
        res = detect_anomaly(row.to_dict())
        attack_results.append(res)
        
    # Calculate confusion matrix components
    # Anomaly = Positive class, Normal = Negative class
    TN = sum(1 for r in normal_results if not r["is_anomaly"])
    FP = sum(1 for r in normal_results if r["is_anomaly"])
    
    TP = sum(1 for r in attack_results if r["is_anomaly"])
    FN = sum(1 for r in attack_results if not r["is_anomaly"])
    
    total = TP + TN + FP + FN
    
    accuracy = (TP + TN) / total
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
    
    print("\n" + "="*40)
    print("           EVALUATION METRICS")
    print("="*40)
    print(f"True Negatives (TN)  : {TN} (Benign classified as normal)")
    print(f"False Positives (FP) : {FP} (Benign flagged as threat)")
    print(f"True Positives (TP)  : {TP} (Attacks flagged as threat)")
    print(f"False Negatives (FN) : {FN} (Attacks missed)")
    print("-"*40)
    print(f"Accuracy             : {accuracy:.4%}")
    print(f"Precision            : {precision:.4%}")
    print(f"Recall (Sensitivity) : {recall:.4%}")
    print(f"F1-Score             : {f1:.4%}")
    print(f"False Positive Rate  : {fpr:.4%}")
    print("="*40)

if __name__ == "__main__":
    evaluate()
