import sys
import time
import json
import httpx
from pathlib import Path

# Force UTF-8 for terminal colors
if hasattr(sys.stdout, "reconfigure") and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

print("="*60)
print("🎬 AEGIS-FUSION DEMO CHOREOGRAPHER ONLINE 🎬")
print("="*60)

API_BASE = "http://localhost:8000"
DATA_PATH = Path("../data/demo_activity_stream.jsonl")

# Colors
GREEN = "\033[32;1m"
CYAN = "\033[36m"
RED = "\033[31;1m"
YELLOW = "\033[33;1m"
RESET = "\033[0m"

def print_step(msg):
    print(f"\n{CYAN}[+] {msg}{RESET}")

def print_alert(msg):
    print(f"{RED}[!] {msg}{RESET}")

def load_normal_logs(n=500):
    logs = []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= n:
                break
            if line.strip():
                logs.append(json.loads(line.strip()))
    return logs

def main():
    normal_logs = load_normal_logs(500)
    
    # 1. Blast logs via normal stream start
    print_step("Phase 1: Starting the backend stream (api/stream/start) to populate dashboard...")
    
    with httpx.Client() as client:
        # Start stream at a decent speed for the dashboard (e.g. 10-20 logs/sec)
        # The user's backend handles it with 64-tensor mapping.
        t0 = time.time()
        res = client.post(f"{API_BASE}/api/stream/start?speed=0.05", timeout=10.0)
        t1 = time.time()
        
        if res.status_code in [200, 409]: # 409 means already running
            print(f"    → Stream Status: {res.status_code} | {res.json()}")
        else:
            print(f"    → Error: {res.status_code} | {res.text}")
    
    print_step("Waiting 5 seconds for dashboard to show streaming logs...")
    time.sleep(5.0)

    # 2. Anomaly 1: Insider Threat (XAI Focus)
    print_step("Injecting Zero-Day Anomaly 1: The Insider Threat (XAI Focus)...")
    
    # We take a base log and mutate it
    anomaly_1 = json.loads(json.dumps(normal_logs[0]))
    uid_1 = "emp_0077"
    anomaly_1["actor"]["user"]["uid"] = uid_1
    anomaly_1["actor"]["user"]["department"] = "Finance"
    anomaly_1["timestamp"] = "2026-04-12T02:00:00.000Z"  # Sunday, 2 AM (is_weekend=1, is_out_of_hours=1)
    anomaly_1["resource"]["volume_mb"] = 50000.0  # Massive volume
    anomaly_1["resource"]["name"] = "Q4_Financial_Summary.xlsx"
    anomaly_1["action"]["type"] = "file_download"

    with httpx.Client() as client:
        client.post(f"{API_BASE}/api/ingest_batch", json=[anomaly_1], timeout=10.0)
    
    print_alert("Insider threat injected! Waiting 10 seconds for LLM narrative & UI Heatmap...")
    time.sleep(10.0)

    # 3. Anomaly 2: The Hijacked Session (Behavioral Focus)
    print_step("Injecting Anomaly 2: The Hijacked Session (Behavioral Focus)...")
    
    uid_2 = "emp_0088"
    # First, establish normal baseline in London
    baseline = json.loads(json.dumps(normal_logs[1]))
    baseline["actor"]["user"]["uid"] = uid_2
    baseline["timestamp"] = "2026-04-15T10:00:00.000Z"
    baseline["context"]["location"] = "London"
    baseline["enrichments"]["aegis_telemetry"]["typing_cadence_variance"] = 0.05

    with httpx.Client() as client:
        client.post(f"{API_BASE}/api/ingest_batch", json=[baseline], timeout=10.0)

    time.sleep(1.0) # wait a sec to simulate time gap

    # Now, impossible travel + biometric spike
    anomaly_2 = json.loads(json.dumps(baseline))
    anomaly_2["timestamp"] = "2026-04-15T10:00:10.000Z" # 10 seconds later
    anomaly_2["context"]["location"] = "Tokyo" # Impossible travel
    anomaly_2["enrichments"]["aegis_telemetry"]["typing_cadence_variance"] = 1.99 # Huge spike in typing variance
    anomaly_2["action"]["type"] = "refund_process"

    with httpx.Client() as client:
        client.post(f"{API_BASE}/api/ingest_batch", json=[anomaly_2], timeout=10.0)

    print_alert("Hijacked session injected! Waiting 10 seconds for LLM & UI...")
    time.sleep(10.0)

    # 4. The Finale
    print_step(f"Finale: Calling SOAR isolate for {uid_2}...")
    with httpx.Client() as client:
        client.post(f"{API_BASE}/api/isolate/{uid_2}", timeout=10.0)
    
    print_step("Finale: Shattering the Merkle Chain...")
    with httpx.Client() as client:
        client.post(f"{API_BASE}/api/tamper", timeout=10.0)

    print(f"\n{GREEN}[✔] Demo Choreography Complete! Drop the mic. 🎤{RESET}")

if __name__ == "__main__":
    main()
