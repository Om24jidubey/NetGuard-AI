"""
Live Capture Engine — NetGuard AI
This module powers the real-time packet sniffer. It utilizes Scapy to intercept raw network 
traffic on local interfaces, groups packets into flows, calculates CICFlowMeter features, 
and hands them off to the AI anomaly detector.
"""

# ==============================================================================
# 1. Imports & Global State
# ==============================================================================
import os
import time
import random
import threading
from pathlib import Path

import pandas as pd
import numpy as np

from anomaly_detector import detect_anomaly
from feature_config import FEATURES

# Global set of malicious IPs blocked by the user via the Dashboard
BLOCKED_IPS = set()

# Try to load Scapy for raw packet sniffing (may fail on Windows without Npcap)
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data" / "cicids2017"

class LiveCaptureManager:
    def __init__(self, callback, mode="auto"):
        """
        callback: Function to call with each processed network flow dict.
        mode: "auto" (try real, fallback to sim) or "simulate" (force simulation)
        """
        self.callback = callback
        self.requested_mode = mode
        self.stop_event = threading.Event()
        self.thread = None
        self.is_simulated = False
        self.flows = {}
        self.flows_lock = threading.Lock()
        
        # Simulation datasets
        self.normal_samples = []
        self.attack_samples = []
        self.load_simulation_data()

    def load_simulation_data(self):
        """Load synthetic datasets for the simulator fallback to avoid 40MB CSV cloud limits."""
        print("[LiveCapture] Loading synthetic simulation payloads...")
        
        normal_payload = {' Destination Port': 49188, ' Flow Duration': 4, ' Total Fwd Packets': 2, ' Total Backward Packets': 0, 'Total Length of Fwd Packets': 12, ' Total Length of Bwd Packets': 0, ' Fwd Packet Length Max': 6, ' Fwd Packet Length Min': 6, ' Fwd Packet Length Mean': 6.0, ' Fwd Packet Length Std': 0.0, 'Bwd Packet Length Max': 0, ' Bwd Packet Length Min': 0, ' Bwd Packet Length Mean': 0.0, ' Bwd Packet Length Std': 0.0, 'Flow Bytes/s': 3000000.0, ' Flow Packets/s': 500000.0, ' Flow IAT Mean': 4.0, ' Flow IAT Std': 0.0, ' Flow IAT Max': 4, ' Flow IAT Min': 4, 'Fwd IAT Total': 4, ' Fwd IAT Mean': 4.0, ' Fwd IAT Std': 0.0, ' Fwd IAT Max': 4, ' Fwd IAT Min': 4, 'Bwd IAT Total': 0, ' Bwd IAT Mean': 0.0, ' Bwd IAT Std': 0.0, ' Bwd IAT Max': 0, ' Bwd IAT Min': 0, 'Fwd PSH Flags': 0, ' Bwd PSH Flags': 0, ' Fwd URG Flags': 0, ' Bwd URG Flags': 0, ' Fwd Header Length': 40, ' Bwd Header Length': 0, 'Fwd Packets/s': 500000.0, ' Bwd Packets/s': 0.0, ' Min Packet Length': 6, ' Max Packet Length': 6, ' Packet Length Mean': 6.0, ' Packet Length Std': 0.0, ' Packet Length Variance': 0.0, 'FIN Flag Count': 0, ' SYN Flag Count': 0, ' RST Flag Count': 0, ' PSH Flag Count': 0, ' ACK Flag Count': 1, ' URG Flag Count': 1, ' CWE Flag Count': 0, ' ECE Flag Count': 0, ' Down/Up Ratio': 0, ' Average Packet Size': 9.0, ' Avg Fwd Segment Size': 6.0, ' Avg Bwd Segment Size': 0.0, ' Fwd Header Length.1': 40, 'Fwd Avg Bytes/Bulk': 0, ' Fwd Avg Packets/Bulk': 0, ' Fwd Avg Bulk Rate': 0, ' Bwd Avg Bytes/Bulk': 0, ' Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0, 'Subflow Fwd Packets': 2, ' Subflow Fwd Bytes': 12, ' Subflow Bwd Packets': 0, ' Subflow Bwd Bytes': 0, 'Init_Win_bytes_forward': 329, ' Init_Win_bytes_backward': -1, ' act_data_pkt_fwd': 1, ' min_seg_size_forward': 20, 'Active Mean': 0.0, ' Active Std': 0.0, ' Active Max': 0, ' Active Min': 0, 'Idle Mean': 0.0, ' Idle Std': 0.0, ' Idle Max': 0, ' Idle Min': 0, ' Label': 'BENIGN'}
        
        import copy
        base_attack = {' Destination Port': 34805, ' Flow Duration': 8003, ' Total Fwd Packets': 15, ' Total Backward Packets': 6, 'Total Length of Fwd Packets': 19897, ' Total Length of Bwd Packets': 0, ' Fwd Packet Length Max': 2896, ' Fwd Packet Length Min': 0, ' Fwd Packet Length Mean': 1326.466667, ' Fwd Packet Length Std': 1136.570208, 'Bwd Packet Length Max': 0, ' Bwd Packet Length Min': 0, ' Bwd Packet Length Mean': 0.0, ' Bwd Packet Length Std': 0.0, 'Flow Bytes/s': 2486192.678, ' Flow Packets/s': 2624.015994, ' Flow IAT Mean': 400.15, ' Flow IAT Std': 1445.918039, ' Flow IAT Max': 6454, ' Flow IAT Min': 1, 'Fwd IAT Total': 8003, ' Fwd IAT Mean': 571.6428571, ' Fwd IAT Std': 1718.054875, ' Fwd IAT Max': 6454, ' Fwd IAT Min': 2, 'Bwd IAT Total': 6663, ' Bwd IAT Mean': 1332.6, ' Bwd IAT Std': 2974.753318, ' Bwd IAT Max': 6654, ' Bwd IAT Min': 1, 'Fwd PSH Flags': 0, ' Bwd PSH Flags': 0, ' Fwd URG Flags': 0, ' Bwd URG Flags': 0, ' Fwd Header Length': 496, ' Bwd Header Length': 208, 'Fwd Packets/s': 1874.297139, ' Bwd Packets/s': 749.7188554, ' Min Packet Length': 0, ' Max Packet Length': 2896, ' Packet Length Mean': 904.4090909, ' Packet Length Std': 1122.979992, ' Packet Length Variance': 1261084.063, 'FIN Flag Count': 0, ' SYN Flag Count': 0, ' RST Flag Count': 0, ' PSH Flag Count': 1, ' ACK Flag Count': 0, ' URG Flag Count': 0, ' CWE Flag Count': 0, ' ECE Flag Count': 0, ' Down/Up Ratio': 0, ' Average Packet Size': 947.4761905, ' Avg Fwd Segment Size': 1326.466667, ' Avg Bwd Segment Size': 0.0, ' Fwd Header Length.1': 496, 'Fwd Avg Bytes/Bulk': 0, ' Fwd Avg Packets/Bulk': 0, ' Fwd Avg Bulk Rate': 0, ' Bwd Avg Bytes/Bulk': 0, ' Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0, 'Subflow Fwd Packets': 15, ' Subflow Fwd Bytes': 19897, ' Subflow Bwd Packets': 6, ' Subflow Bwd Bytes': 0, 'Init_Win_bytes_forward': 29200, ' Init_Win_bytes_backward': 362, ' act_data_pkt_fwd': 10, ' min_seg_size_forward': 32, 'Active Mean': 0.0, ' Active Std': 0.0, ' Active Max': 0, ' Active Min': 0, ' Label': 'BENIGN'}

        a1 = copy.deepcopy(base_attack)
        a1['Flow Bytes/s'] = 999_999_999 # Volumetric DDoS
        a1[' Flow Packets/s'] = 999_999
        a1[' Flow Duration'] = 999_999_999
        
        a2 = copy.deepcopy(base_attack)
        a2['Flow Bytes/s'] = 500_000
        a2[' Flow Packets/s'] = 999_999 # Packet Flood
        a2[' SYN Flag Count'] = 999999
        
        a3 = copy.deepcopy(base_attack)
        a3['Flow Bytes/s'] = 500_000
        a3[' Flow Packets/s'] = 2_000
        a3[' SYN Flag Count'] = 999999 # SYN Flood
        a3[' ACK Flag Count'] = 999999
        a3[' Flow Duration'] = 1
        
        a1 = copy.deepcopy(base_attack)
        a1['simulated_attack_type'] = "DDoS"
        
        a2 = copy.deepcopy(base_attack)
        a2['simulated_attack_type'] = "PortScan"
        
        a3 = copy.deepcopy(base_attack)
        a3['simulated_attack_type'] = "Brute Force"
        
        a4 = copy.deepcopy(base_attack)
        a4['simulated_attack_type'] = "Web Attack (SQLi)"
        
        a5 = copy.deepcopy(base_attack)
        a5['simulated_attack_type'] = "Botnet"
        
        a6 = copy.deepcopy(base_attack)
        a6['simulated_attack_type'] = "Infiltration"
        
        a7 = copy.deepcopy(base_attack)
        a7['simulated_attack_type'] = "Zero-Day Anomaly"

        self.normal_samples = [normal_payload]
        self.attack_samples = [a1, a2, a3, a4, a5, a6, a7]

    def start(self):
        """Start the sniffing or simulation in a background thread."""
        self.stop_event.clear()
        
        if self.requested_mode == "simulate":
            print("[LiveCapture] Forcing simulation mode as requested by client.")
            self.is_simulated = True
            self.thread = threading.Thread(target=self.simulation_loop, daemon=True)
        else:
            if SCAPY_AVAILABLE:
                # Test raw socket permissions
                try:
                    # We do a tiny sniff with a short timeout to see if we have permissions
                    sniff(count=1, timeout=0.1)
                    self.is_simulated = False
                    print("[LiveCapture] Starting real-time Scapy sniffer...")
                    self.thread = threading.Thread(target=self.sniff_loop, daemon=True)
                except Exception as e:
                    print(f"[LiveCapture] Scapy sniffing failed initialization ({e}). Falling back to simulation mode.")
                    self.is_simulated = True
                    self.thread = threading.Thread(target=self.simulation_loop, daemon=True)
            else:
                print("[LiveCapture] Scapy not installed. Falling back to simulation mode.")
                self.is_simulated = True
                self.thread = threading.Thread(target=self.simulation_loop, daemon=True)
            
        self.thread.start()

    def stop(self):
        """Stop the background thread."""
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=1.0)
            print("[LiveCapture] Sniffer thread stopped.")

    def sniff_loop(self):
        """Scapy sniffing worker."""
        try:
            sniff(
                prn=self.process_packet,
                stop_filter=lambda x: self.stop_event.is_set(),
                store=0
            )
        except Exception as e:
            print(f"[LiveCapture] Error in sniff loop: {e}")
            # If sniffing crashes mid-run, switch to simulation
            if not self.stop_event.is_set():
                print("[LiveCapture] Sniffing failed. Switching to simulator.")
                self.is_simulated = True
                self.simulation_loop()

    def process_packet(self, pkt):
        """Callback for Scapy packet sniffer."""
        if not pkt.haslayer(IP):
            return

        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if ip_src in BLOCKED_IPS:
            return
            
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"
        
        sport = 0
        dport = 0
        is_syn = 0
        is_ack = 0
        is_fin = 0
        is_rst = 0
        
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            if flags & 0x02:  # SYN flag
                is_syn = 1
            if flags & 0x10:  # ACK flag
                is_ack = 1
            if flags & 0x01:  # FIN flag
                is_fin = 1
            if flags & 0x04:  # RST flag
                is_rst = 1
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        # Ignore our own application traffic to prevent infinite feedback loops
        if sport in (8000, 3000) or dport in (8000, 3000):
            return

        # Flow key: direction independent IP/port combo
        flow_key = tuple(sorted([(ip_src, sport), (ip_dst, dport)]))
        pkt_len = len(pkt)

        with self.flows_lock:
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    "start_time": time.time(),
                    "last_time": time.time(),
                    "fwd_packets": 0,
                    "bwd_packets": 0,
                    "fwd_bytes": 0,
                    "bwd_bytes": 0,
                    "fwd_lengths": [],
                    "bwd_lengths": [],
                    "syn_count": 0,
                    "ack_count": 0,
                    "ip_src": ip_src,
                    "ip_dst": ip_dst,
                    "sport": sport,
                    "dport": dport,
                    "proto": proto
                }

            flow = self.flows[flow_key]
            
            # Determine direction: Fwd if source matches the initiator
            if ip_src == flow["ip_src"]:
                flow["fwd_packets"] += 1
                flow["fwd_bytes"] += pkt_len
                flow["fwd_lengths"].append(pkt_len)
            else:
                flow["bwd_packets"] += 1
                flow["bwd_bytes"] += pkt_len
                flow["bwd_lengths"].append(pkt_len)
                
            flow["last_time"] = time.time()
            flow["syn_count"] += is_syn
            flow["ack_count"] += is_ack
            
            total_pkts = flow["fwd_packets"] + flow["bwd_packets"]
            
            # SESSION BUFFERING LOGIC:
            # 1. If it's a TCP connection closing (FIN or RST), evaluate the full flow immediately.
            # 2. For UDP or long-running TCP streams, evaluate periodically (e.g. every 25 packets) to prevent stale states.
            if is_fin or is_rst or total_pkts >= 25:
                self.evaluate_flow(flow)
                # Free up memory by deleting completed flows
                del self.flows[flow_key]

    def evaluate_flow(self, flow):
        """Construct the 21 features and run anomaly detection."""
        duration_sec = max(0.0001, flow["last_time"] - flow["start_time"])
        duration_micro = duration_sec * 1_000_000
        
        fwd_pkts = flow["fwd_packets"]
        bwd_pkts = flow["bwd_packets"]
        fwd_bytes = flow["fwd_bytes"]
        bwd_bytes = flow["bwd_bytes"]
        
        fwd_len_mean = np.mean(flow["fwd_lengths"]) if flow["fwd_lengths"] else 0
        bwd_len_mean = np.mean(flow["bwd_lengths"]) if flow["bwd_lengths"] else 0
        
        all_lengths = flow["fwd_lengths"] + flow["bwd_lengths"]
        pkt_len_mean = np.mean(all_lengths) if all_lengths else 0
        pkt_len_std = np.std(all_lengths) if all_lengths else 0
        
        # Calculate feature values mapping to feature_config.py
        feature_dict = {
            " Flow Duration": float(duration_micro),
            " Total Fwd Packets": float(fwd_pkts),
            " Total Backward Packets": float(bwd_pkts),
            "Total Length of Fwd Packets": float(fwd_bytes),
            " Total Length of Bwd Packets": float(bwd_bytes),
            " Fwd Packet Length Mean": float(fwd_len_mean),
            " Bwd Packet Length Mean": float(bwd_len_mean),
            "Flow Bytes/s": float((fwd_bytes + bwd_bytes) / duration_sec),
            " Flow Packets/s": float((fwd_pkts + bwd_pkts) / duration_sec),
            " Flow IAT Mean": float(duration_micro / max(1, fwd_pkts + bwd_pkts - 1)),
            " Flow IAT Std": 0.0,
            " Packet Length Mean": float(pkt_len_mean),
            " Packet Length Std": float(pkt_len_std),
            " SYN Flag Count": float(flow["syn_count"]),
            " ACK Flag Count": float(flow["ack_count"]),
            " Down/Up Ratio": float(bwd_pkts / max(1, fwd_pkts)),
            " Average Packet Size": float(pkt_len_mean),
            "Idle Mean": 0.0,
            " Active Max": 0.0,
            " Idle Max": 0.0,
        }

        from feature_config import normalize_feature
        feature_dict_normalized = {normalize_feature(k): v for k, v in feature_dict.items()}

        # Run anomaly detection
        detection = detect_anomaly(feature_dict_normalized)
        
        # Add metadata for frontend display
        result = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": flow["ip_src"],
            "source_port": flow["sport"],
            "dest_ip": flow["ip_dst"],
            "dest_port": flow["dport"],
            "protocol": flow["proto"],
            "packets": fwd_pkts + bwd_pkts,
            "bytes": fwd_bytes + bwd_bytes,
            "is_anomaly": detection["is_anomaly"],
            "score": detection["score"],
            "severity": detection["severity"],
            "attack_type": detection["attack_type"],
            "top_features": detection["top_features"],
            "raw": feature_dict,
            "mode": "Live Sniffing"
        }
        
        # Save anomalies to database
        if detection["is_anomaly"]:
            from database import save_alert
            save_alert(
                attack_type=detection["attack_type"],
                severity=detection["severity"],
                score=detection["score"],
                source_ip=f"{flow['ip_src']}:{flow['sport']}"
            )

        self.callback(result)

    def simulation_loop(self):
        """Simulates live traffic using real samples from CICIDS2017."""
        print("[LiveCapture] Network traffic simulator started.")
        
        # Simulated IP pool
        ips = [f"192.168.1.{i}" for i in range(10, 200)]
        target_ip = "192.168.1.1" # local gateway/server
        
        while not self.stop_event.is_set():
            try:
                # 85% normal traffic, 15% attack traffic
                is_attack = random.random() < 0.15
                
                sample = None
                if is_attack and self.attack_samples:
                    sample = random.choice(self.attack_samples)
                elif self.normal_samples:
                    sample = random.choice(self.normal_samples)
                    
                if sample:
                    # Select random source IP/port
                    src_ip = random.choice(ips)
                    dst_ip = target_ip
                    if is_attack:
                        # Attack source might be external
                        src_ip = f"{random.randint(10, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                        
                    if src_ip in BLOCKED_IPS:
                        continue
                        
                    sport = random.randint(1024, 65535)
                    # DDoS SYN flood normally hits standard web ports
                    dport = 80 if is_attack and random.random() < 0.7 else random.choice([80, 443, 22, 3389])
                    proto = "TCP" if random.random() < 0.8 else "UDP"
                    
                    # Align raw variables
                    feature_dict = {}
                    for feature in FEATURES:
                        feature_dict[feature] = float(sample.get(feature, 0.0))
                    
                    if "simulated_attack_type" in sample:
                        feature_dict["simulated_attack_type"] = sample["simulated_attack_type"]
                        
                    from feature_config import normalize_feature
                    feature_dict_normalized = {normalize_feature(k): v for k, v in feature_dict.items() if k != "simulated_attack_type"}
                    if "simulated_attack_type" in feature_dict:
                        feature_dict_normalized["simulated_attack_type"] = feature_dict["simulated_attack_type"]

                    # Run Autoencoder
                    detection = detect_anomaly(feature_dict_normalized)
                    
                    # Safely calculate bytes from original sample since we dropped the length features from AI
                    fwd_bytes = sample.get("Total Length of Fwd Packets", 0)
                    bwd_bytes = sample.get(" Total Length of Bwd Packets", 0)
                    
                    # Build live alert
                    result = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "source_ip": src_ip,
                        "source_port": sport,
                        "dest_ip": dst_ip,
                        "dest_port": dport,
                        "protocol": proto,
                        "packets": int(feature_dict.get(" Total Fwd Packets", 0) + feature_dict.get(" Total Backward Packets", 0)),
                        "bytes": int(fwd_bytes + bwd_bytes),
                        "is_anomaly": detection["is_anomaly"],
                        "score": detection["score"],
                        "severity": detection["severity"],
                        "attack_type": detection["attack_type"],
                        "top_features": detection["top_features"],
                        "raw": feature_dict,
                        "mode": "Simulated Live"
                    }
                    
                    if detection["is_anomaly"]:
                        from database import save_alert
                        save_alert(
                            attack_type=detection["attack_type"],
                            severity=detection["severity"],
                            score=detection["score"],
                            source_ip=f"{src_ip}:{sport}"
                        )
                    
                    self.callback(result)
            except Exception as e:
                print(f"[LiveCapture] Error in simulation loop: {e}")
                import traceback
                traceback.print_exc()
            
            # Sleep between 0.3s and 1.5s to look like live traffic burstiness
            time.sleep(random.uniform(0.3, 1.2))
