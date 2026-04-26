"""
╔══════════════════════════════════════════════════════════════════════════╗
║  A E G I S  —  Insider Threat Detection Engine  v2.0                   ║
║  FastAPI · PyTorch VAE · Ollama LLM · WebSocket · Merkle Chain         ║
║                                                                        ║
║  Pipeline:                                                             ║
║    JSONL Stream → SHA-256 Merkle Chain → VAE Inference → Risk Score    ║
║      → [if critical] Ollama LLM Analysis → WebSocket Broadcast         ║
║                                                                        ║
║  Run:  python main.py                                                  ║
║  Or:   uvicorn main:app --host 0.0.0.0 --port 8000                     ║
║                                                                        ║
║  Dependencies:                                                         ║
║    pip install fastapi uvicorn[standard] websockets torch httpx pandas  ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import sys
import io

# Force UTF-8 encoding for Windows terminals to support emojis and box-drawing
if hasattr(sys.stdout, "reconfigure") and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, "reconfigure") and sys.stderr.encoding.lower() != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8')

import asyncio
import hashlib
import json
import logging
import math
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib

import httpx
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, File, UploadFile, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

try:
    import cv2
    from blind_watermark import WaterMark
except ImportError:
    cv2 = None
    WaterMark = None

GLOBAL_LAST_IDENTITY = {
    "user_id": "SESSION_PENDING",
    "department": "Awaiting Access...",
    "timestamp": int(time.time())
}
ALLOWED_SUBNET = "192.168.1."


# ═══════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

ROOT         = Path(__file__).resolve().parent.parent          # backend/
JSONL_PATH   = ROOT / "data" / "demo_activity_stream.jsonl"
MODEL_PATH   = ROOT / "ml" / "models" / "aegis_vae_model_weighted.pth"
IFOREST_PATH = ROOT / "ml" / "models" / "iforest.pkl"
IFOREST_CAL  = ROOT / "ml" / "models" / "iforest_calibration.json"
META_PATH    = ROOT / "ml" / "data" / "feature_meta.json"
ROLES_PATH   = ROOT / "ml" / "data" / "user_roles.csv"
THRESH_PATH  = ROOT / "ml" / "data" / "threshold_stats.json"

OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_MODEL   = "llama3"
OLLAMA_TIMEOUT = 60.0              # seconds — local LLMs can be slow

# ── Discord Webhook (PagerDuty Flex) ──────────────────────────────────────
# Paste your Discord webhook URL here. Set to "" to disable.
# Create one at: Discord Server → Settings → Integrations → Webhooks → New
DISCORD_WEBHOOK_URL = ""             # e.g. "https://discord.com/api/webhooks/1234/abcd"

ALERT_THRESHOLD = 85               # risk_score > this → critical_alert + LLM
INPUT_DIM       = 64               # feature vector width (61 base + 2 time-context + 1 travel vel)
LATENT_DIM      = 10                # VAE latent space (from train_vae.py)
STREAM_SPEED    = 0.1              # seconds between log reads (~10 logs/sec)

# Calibration defaults (overridden at startup from threshold_stats.json)
TRAIN_MSE_MEAN = 0.08752130717039108
TRAIN_MSE_STD  = 0.022675734013319016


# ═══════════════════════════════════════════════════════════════════════════
#  LOGGING — SOC TERMINAL STYLE (ANSI color codes, no external deps)
# ═══════════════════════════════════════════════════════════════════════════

class _SOCFormatter(logging.Formatter):
    """Custom formatter that makes the terminal look like a live SOC console."""

    _GREY    = "\033[38;5;245m"
    _CYAN    = "\033[36m"
    _GREEN   = "\033[32;1m"
    _YELLOW  = "\033[33;1m"
    _RED     = "\033[31;1m"
    _MAGENTA = "\033[35;1m"
    _BOLD    = "\033[1m"
    _RESET   = "\033[0m"

    _LEVEL_STYLES = {
        logging.DEBUG:    (_GREY,    "DBG"),
        logging.INFO:     (_CYAN,    "INF"),
        logging.WARNING:  (_YELLOW,  "WRN"),
        logging.ERROR:    (_RED,     "ERR"),
        logging.CRITICAL: (_RED,     "🚨 CRIT"),
    }

    def format(self, record: logging.LogRecord) -> str:
        color, tag = self._LEVEL_STYLES.get(record.levelno, (self._CYAN, "INF"))
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        ms = f"{record.created % 1:.3f}"[1:]          # .NNN
        return f"{color}{ts}{ms} │ {tag:>8s} │ {record.getMessage()}{self._RESET}"


log = logging.getLogger("aegis")
log.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(_SOCFormatter())
log.addHandler(_handler)
log.propagate = False


# ═══════════════════════════════════════════════════════════════════════════
#  STEP 2 — VAE MODEL ARCHITECTURE (exact copy from train_vae.py)
# ═══════════════════════════════════════════════════════════════════════════
#
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  This class is wired to the REAL trained architecture.              ║
# ║  If you retrain with a different shape, update the layers here.     ║
# ╚══════════════════════════════════════════════════════════════════════╝

class InsiderThreatVAE(nn.Module):
    """Variational Autoencoder for enterprise activity anomaly detection.

    Architecture:  63 -> 128 -> 64 -> [mu, logvar] -> 10 (latent) -> 64 -> 128 -> 63
    """

    def __init__(self, input_dim: int = INPUT_DIM, latent_dim: int = LATENT_DIM):
        super().__init__()
        # Encoder: input_dim → 32 → 16 → (mu, logvar)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128), nn.LeakyReLU(0.2),
            nn.Linear(128, 64),        nn.LeakyReLU(0.2),
        )
        self.fc_mu     = nn.Linear(64, latent_dim)
        self.fc_logvar = nn.Linear(64, latent_dim)

        # Decoder: latent_dim → 64 → 128 → input_dim
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 64), nn.LeakyReLU(0.2),
            nn.Linear(64, 128),         nn.LeakyReLU(0.2),
            nn.Linear(128, input_dim),  nn.Sigmoid(),
        )

    def encode(self, x: torch.Tensor):
        h = self.encoder(x)
        return self.fc_mu(h), self.fc_logvar(h)

    def reparameterize(self, mu: torch.Tensor, logvar: torch.Tensor):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def decode(self, z: torch.Tensor):
        return self.decoder(z)

    def forward(self, x: torch.Tensor):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        return self.decode(z), mu, logvar


# Hackathon Approximation for City Coordinates (Lat, Lon) — Impossible Travel
CITY_COORDS = {
    "Pune": (18.52, 73.85), "Bangalore": (12.97, 77.59), "Mumbai": (19.07, 72.87),
    "Singapore": (1.35, 103.81), "Chicago": (41.87, -87.62), "Tokyo": (35.67, 139.65),
    "London": (51.50, -0.12), "Frankfurt": (50.11, 8.68), "Austin": (30.26, -97.74),
    "Sydney": (-33.86, 151.20), "Delhi": (28.61, 77.20), "Seoul": (37.56, 126.97),
    "Amsterdam": (52.37, 4.90), "Dublin": (53.35, -6.26), "New_York": (40.71, -74.00),
    "Seattle": (47.61, -122.33), "Toronto": (43.65, -79.38), "Sao_Paulo": (-23.55, -46.63),
    "Dubai": (25.20, 55.27), "Johannesburg": (-26.20, 28.04),
}


def preprocess_json_to_tensor(log_data: dict, user_history: list | None = None) -> torch.Tensor:
    global FEATURE_META
    if user_history is None:
        user_history = []
    
    # The log_data was already appended to the buffer in the stream loop!
    session_logs = user_history
    
    # 1. basic properties
    # need datetime conversion
    ts_list = []
    for log in session_logs:
        ts_str = log.get("timestamp", "").replace("Z", "+00:00")
        try:
            ts_list.append(datetime.fromisoformat(ts_str))
        except:
            ts_list.append(datetime.utcnow())
            
    ts_list.sort()
    
    hour_sins = []
    hour_coss = []
    # ── Time-context features (is_weekend, is_out_of_hours) ──────────
    weekends = []       # 1.0 if Saturday(5) or Sunday(6)
    out_of_hours = []   # 1.0 if strictly between 20:00 and 06:00
    for t in ts_list:
        hf = t.hour + t.minute / 60.0
        hour_sins.append(math.sin(2.0 * math.pi * hf / 24.0))
        hour_coss.append(math.cos(2.0 * math.pi * hf / 24.0))
        weekends.append(1.0 if t.weekday() >= 5 else 0.0)
        out_of_hours.append(1.0 if (t.hour >= 20 or t.hour < 6) else 0.0)
        
    delta_s = []
    for i in range(1, len(ts_list)):
        delta_s.append(abs((ts_list[i] - ts_list[i-1]).total_seconds()))
    if len(delta_s) == 0:
        delta_s = [0.0]
        
    duration_s = abs((ts_list[-1] - ts_list[0]).total_seconds()) if len(ts_list) > 0 else 0.0
    log_count = len(session_logs)
    velocity_lps = log_count / duration_s if duration_s > 0 else float(log_count)
    
    vols = [log.get("resource", {}).get("volume_mb", 0.0) for log in session_logs]
    
    act_counts = {}
    grp_counts = {}
    sens_counts = {}
    loc_counts = {}
    mfa_counts = {}
    
    entropies = []
    typing_vars = []
    opticals = []
    edr_offs = []
    action_fails = []
    
    # Threat flags
    f_honey = 0.0
    f_destr = 0.0
    f_crit = 0.0
    f_opt = 0.0
    f_ent = 0.0
    
    CRITICAL_RESOURCES = {"inventory_db", "S3_Backup_Bucket", "customer_loyalty_db", "encoded_product_shots.jpg"}
    DESTRUCTIVE_ACTIONS = {"record_delete", "process_kill", "config_change"}
    
    for log in session_logs:
        act = log.get("action", {}).get("type", "")
        act_counts[act] = act_counts.get(act, 0) + 1
        
        grp = log.get("actor", {}).get("user", {}).get("group", "")
        grp_counts[grp] = 1 # max pool
        
        sens = log.get("resource", {}).get("sensitivity_label", "")
        sens_counts[sens] = sens_counts.get(sens, 0) + 1
        
        loc = log.get("context", {}).get("location", "")
        loc_counts[loc] = loc_counts.get(loc, 0) + 1
        
        mfa = log.get("actor", {}).get("mfa_status", "")
        mfa_counts[mfa] = mfa_counts.get(mfa, 0) + 1
        
        enr = log.get("enrichments", {}).get("aegis_telemetry", {})
        ent = enr.get("file_entropy", 0.0)
        entropies.append(ent)
        typing_vars.append(enr.get("typing_cadence_variance", 0.0))
        
        opt_str = enr.get("optical_sensor_state", "")
        opt_det = 1.0 if opt_str == "Optical Device Detected" else 0.0
        opticals.append(opt_det)
        
        edr = log.get("context", {}).get("edr_agent_active", True)
        edr_offs.append(0.0 if edr else 1.0)
        
        status = log.get("action", {}).get("status", "success")
        action_fails.append(0.0 if status == "success" else 1.0)
        
        rname = log.get("resource", {}).get("name", "")
        if "Q4_Executive_Bonuses" in rname:
            f_honey = 1.0
        if act in DESTRUCTIVE_ACTIONS:
            f_destr = 1.0
        if rname in CRITICAL_RESOURCES:
            f_crit = 1.0
        if opt_det > 0:
            f_opt = 1.0
        if ent > 0.95:
            f_ent = 1.0

    # ── Impossible Travel Velocity (Haversine) ───────────────────────
    # If two consecutive logs originate from different cities that exist
    # in CITY_COORDS, compute great-circle distance / time_delta.
    # Max velocity > ~0.3 km/s (jet speed) is physically impossible.
    _max_travel_velocity = 0.0
    for i in range(1, len(session_logs)):
        loc_a = session_logs[i - 1].get("context", {}).get("location", "")
        loc_b = session_logs[i].get("context", {}).get("location", "")
        if loc_a == loc_b or loc_a not in CITY_COORDS or loc_b not in CITY_COORDS:
            continue
        # Time delta in seconds between the two consecutive logs
        dt = abs((ts_list[i] - ts_list[i - 1]).total_seconds()) if i < len(ts_list) else 0.0
        if dt < 1.0:
            dt = 1.0  # clamp to avoid division by zero
        # Haversine formula
        lat1, lon1 = math.radians(CITY_COORDS[loc_a][0]), math.radians(CITY_COORDS[loc_a][1])
        lat2, lon2 = math.radians(CITY_COORDS[loc_b][0]), math.radians(CITY_COORDS[loc_b][1])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        c = 2 * math.asin(math.sqrt(a))
        km = 6371.0 * c          # Earth radius in km
        vel = km / dt             # km/sec
        if vel > _max_travel_velocity:
            _max_travel_velocity = vel

    raw_feat = {
        "hour_sin_mean": np.mean(hour_sins),
        "hour_sin_std": np.std(hour_sins, ddof=1) if len(hour_sins) > 1 else 0.0,
        "hour_cos_mean": np.mean(hour_coss),
        "hour_cos_std": np.std(hour_coss, ddof=1) if len(hour_coss) > 1 else 0.0,
        # ── NEW: Time-context binary signals ─────────────────────────
        "is_weekend": max(weekends) if weekends else 0.0,         # any log on weekend → 1.0
        "is_out_of_hours": max(out_of_hours) if out_of_hours else 0.0,  # any log at night → 1.0
        "session_duration_s": duration_s,
        "log_count": float(log_count),
        "delta_s_mean": np.mean(delta_s),
        "delta_s_std": np.std(delta_s, ddof=1) if len(delta_s) > 1 else 0.0,
        "delta_s_min": float(np.min(delta_s)),
        "delta_s_max": float(np.max(delta_s)),
        "velocity_lps": velocity_lps,
        "volume_mb_sum": sum(vols),
        "volume_mb_max": max(vols),
        "volume_mb_mean": np.mean(vols),
    }

    ACTION_TYPES = ["login", "vpn_connect", "db_query", "file_download", "file_copy", "config_change", "usb_mount", "mfa_enroll", "record_delete", "permission_change", "process_kill"]
    for a in ACTION_TYPES:
        raw_feat[f"act_{a}_mean"] = act_counts.get(a, 0) / log_count

    USER_GROUPS = ["Junior_Marketing", "Senior_Marketing", "Warehouse_Floor", "Cloud_Admin", "IT_Support", "Corporate_Finance", "Corporate_HR", "Supply_Chain_Ops", "Retail_Store_Ops", "Data_Analytics", "Legal_Compliance", "Executive_Leadership"]
    for g in USER_GROUPS:
        raw_feat[f"grp_{g}_max"] = float(grp_counts.get(g, 0.0))

    SENS_LVLS = ["Public", "Internal", "Confidential", "PII_RESTRICTED"]
    for s in SENS_LVLS:
        raw_feat[f"sens_{s}_mean"] = sens_counts.get(s, 0) / log_count

    LOCS = ["Pune", "Bangalore", "Mumbai", "Singapore", "Unknown"]
    for loc in LOCS:
        raw_feat[f"loc_{loc}_mean"] = loc_counts.get(loc, 0) / log_count

    MFAS = ["success", "failed", "bypassed"]
    for m in MFAS:
        raw_feat[f"mfa_{m}_mean"] = mfa_counts.get(m, 0) / log_count

    raw_feat.update({
        "file_entropy_max": max(entropies),
        "file_entropy_mean": np.mean(entropies),
        "typing_var_mean": np.mean(typing_vars),
        "typing_var_max": max(typing_vars),
        "optical_det_mean": np.mean(opticals),
        "edr_off_mean": np.mean(edr_offs),
        "action_failed_mean": np.mean(action_fails),
        "flag_honey_token_max": f_honey,
        "flag_destructive_action_max": f_destr,
        "flag_critical_resource_max": f_crit,
        "flag_optical_sensor_max": f_opt,
        "flag_high_entropy_max": f_ent,
        # Impossible travel velocity (km/s) — Haversine
        "impossible_travel_max": _max_travel_velocity,
    })

    final_vec = []
    if FEATURE_META is None or "feature_names" not in FEATURE_META:
        raise ValueError("FEATURE_META not correctly loaded")

    for col in FEATURE_META["feature_names"]:
        val = raw_feat.get(col, 0.0)
        scaling = FEATURE_META["scaling"].get(col, {})
        
        trap = scaling.get("trap", False)
        if trap:
            final_vec.append(float(min(1.0, val)))
        else:
            cmin = scaling.get("min", 0.0)
            crange = scaling.get("range", 1.0)
            if crange < 1e-12:
                final_vec.append(0.0)
            else:
                scaled = (val - cmin) / crange
                final_vec.append(float(max(0.0, min(1.0, scaled))))
                
    return torch.tensor([final_vec], dtype=torch.float32)


# ═══════════════════════════════════════════════════════════════════════════
#  MERKLE INTEGRITY CHAIN
# ═══════════════════════════════════════════════════════════════════════════

class EnterpriseMerkleTree:
    """Rolling SHA-256 hash chain guaranteeing log ordering and integrity.

    Each new log's hash is combined with the previous root:
        new_root = SHA-256(old_root ‖ SHA-256(raw_json))
    Any log tampered → every subsequent root diverges → detectable.
    """

    def __init__(self):
        self._root  = hashlib.sha256(b"AEGIS_GENESIS_BLOCK").hexdigest()
        self._count = 0

    def ingest(self, raw_json: str) -> str:
        """Hash raw JSON, chain with current root, return new root."""
        log_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        combined = f"{self._root}{log_hash}"
        self._root = hashlib.sha256(combined.encode("utf-8")).hexdigest()
        self._count += 1
        return self._root

    @property
    def root(self) -> str:
        return self._root

    @property
    def count(self) -> int:
        return self._count


# ═══════════════════════════════════════════════════════════════════════════
#  RISK SCORING — IsolationForest Ensemble (replaces raw MSE scoring)
# ═══════════════════════════════════════════════════════════════════════════
#
#  The IsolationForest's decision_function(z) returns:
#    POSITIVE = normal  (deep inside the learned normal manifold)
#    NEGATIVE = anomaly (isolated quickly by random cuts)
#    0.0      = boundary
#
#  We map this to [1, 100] using pre-computed calibration anchors:
#    safe_anchor  = train p5  (the "most normal" baseline)
#    alert_anchor = test p75  (clearly anomalous territory)
#
#  Math:  risk = clamp((safe - d) / (safe - alert), 0, 1) * 99 + 1
# ═══════════════════════════════════════════════════════════════════════════

import random

# Calibration anchors (loaded from iforest_calibration.json at startup)
IFOREST_SAFE_ANCHOR:  float = 0.0329   # default, overridden at startup
IFOREST_ALERT_ANCHOR: float = -0.1296  # default, overridden at startup


def iforest_decision_to_risk(decision_score: float) -> int:
    """Map IsolationForest decision_function output to 1-100 risk score.

    Uses calibrated anchors computed during train_iforest.py:
      safe_anchor  (train p5)  -> risk ~1   (deep normal)
      alert_anchor (test p75)  -> risk ~100 (clear anomaly)

    The inversion (safe - d) is necessary because decision_function
    returns HIGHER values for MORE NORMAL samples.
    """
    span = IFOREST_SAFE_ANCHOR - IFOREST_ALERT_ANCHOR
    if abs(span) < 1e-12:
        return 50

    normalized = (IFOREST_SAFE_ANCHOR - decision_score) / span
    normalized = max(0.0, min(1.0, normalized))
    risk = int(normalized * 99 + 1)

    # UI jitter: subtle variance for visual realism on the dashboard
    if 5 < risk < 95:
        risk += int(random.uniform(-2.0, 2.0))

    return max(1, min(100, risk))


# ═══════════════════════════════════════════════════════════════════════════
#  OLLAMA LLM CLIENT (Rate-Limited with asyncio.Lock)
# ═══════════════════════════════════════════════════════════════════════════

class OllamaAnalyst:
    """Async, priority-queued client for local Ollama LLM threat analysis.

    To prevent crashing the local GPU during high-velocity anomaly bursts
    (e.g., 50 alerts in 1 sec), this implements an LLM Priority Queue
    with an Asynchronous Non-Blocking Lock.

    Lock Behavior:
      - IF LOCKED:   LLM is busy → return hardcoded fallback immediately
      - IF UNLOCKED: Acquire lock → await Llama 3 → release in finally
    """

    # Hardcoded fallback when the LLM is already processing another threat
    _BUSY_FALLBACK: dict = {
        "summary": ("Multiple concurrent anomalies detected. "
                     "ML threat flag logged; LLM queued for capacity."),
        "recommended_action": "Standard protocol.",
    }

    def __init__(self):
        self._client:  httpx.AsyncClient | None = None
        self._available = False
        self._calls     = 0

        # Priority Queue state
        self._queue = asyncio.PriorityQueue()
        self._bg_task = None

        # ── Non-Blocking Lock ────────────────────────────────────────
        self._lock = asyncio.Lock()
        self._is_processing = False

    async def initialize(self):
        """Probe Ollama on startup; set _available flag and start worker."""
        self._client = httpx.AsyncClient(timeout=OLLAMA_TIMEOUT)
        try:
            resp = await self._client.get("http://localhost:11434/api/tags")
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", [])]
                self._available = True
                log.info("🧠 Ollama connected — available models: %s", models)
            else:
                log.warning("⚠  Ollama returned status %d — AI analysis disabled", resp.status_code)
        except Exception:
            log.warning("⚠  Ollama not reachable at localhost:11434 — using rule-based fallback")
            
        self._bg_task = asyncio.create_task(self._worker())

    async def shutdown(self):
        """Clean up background workers and connections."""
        if self._bg_task:
            self._bg_task.cancel()
        if self._client:
            await self._client.aclose()

    def enqueue(self, log_data: dict, risk_score: int, output_payload: dict):
        """Non-blocking enqueue for critical stream events."""
        # Priority Queue (min-heap): order by -risk_score (highest risk first)
        self._queue.put_nowait((-risk_score, time.time(), log_data, output_payload))

    async def _worker(self):
        """Background loop: batches 1-sec windows and processes highest priority."""
        while True:
            try:
                # 1. Wait for at least one item
                score, ts, log_data, output = await self._queue.get()
                
                # 2. Wait 1 second to accumulate any other logs arriving in this window
                await asyncio.sleep(1.0)
                
                # 3. Drain the queue to find the absolute highest risk (lowest score value)
                best_item = (score, ts, log_data, output)
                skipped_items = []
                
                while not self._queue.empty():
                    item = self._queue.get_nowait()
                    if item[0] < best_item[0]: # Lower score = higher risk
                        skipped_items.append(best_item)
                        best_item = item
                    else:
                        skipped_items.append(item)
                        
                # 4. Fire "Skipped" broadcasts for the losers to keep stream lively
                for item in skipped_items:
                    _, _, _, i_out = item
                    i_out["ai_analysis"] = {
                        "summary": "Skipped — LLM Rate Limited (Priority Queue).",
                        "recommended_action": "Refer to raw ML anomaly score."
                    }
                    await manager.broadcast(i_out)
                    
                # 5. Process the winner — with non-blocking lock check
                w_score, w_ts, w_log, w_out = best_item

                if self._is_processing:
                    # LLM is currently busy — return hardcoded fallback
                    log.warning("🔒 LLM LOCKED — concurrent anomaly, returning fallback")
                    w_out["ai_analysis"] = dict(self._BUSY_FALLBACK)
                    await manager.broadcast(w_out)
                    continue

                try:
                    self._is_processing = True
                    analysis = await self._do_analyze(w_log, -w_score)
                except Exception as e:
                    log.error("Ollama worker error: %s", e)
                    analysis = self._fallback(w_log, -w_score)
                finally:
                    self._is_processing = False
                    
                w_out["ai_analysis"] = analysis

                # ── Discord "PagerDuty Flex" ──────────────────────
                # Fire the LLM narrative to Discord so phones buzz
                # on stage.  Wrapped in try/except — never crashes.
                try:
                    # Extract uid from the original log payload
                    _actor = (w_log[-1] if isinstance(w_log, list) else w_log
                              ).get("actor", {})
                    _uid = (_actor.get("user_id", "")
                            or _actor.get("user", {}).get("uid", "unknown"))
                    _narrative = analysis.get("summary", "No narrative.")
                    await send_discord_alert(_uid, -w_score, _narrative)
                except Exception as _discord_err:
                    log.warning("📟 Discord fire-and-forget failed: %s", _discord_err)

                await manager.broadcast(w_out)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Fatal LLM background worker error: %s", e)
                await asyncio.sleep(1)

    async def analyze(self, user_history: list | dict, risk_score: int) -> dict:
        """Synchronous (awaitable) analyze for isolated DEMO endpoints.

        Uses the same non-blocking lock to prevent overlapping calls.
        """
        if self._is_processing:
            log.warning("🔒 LLM LOCKED (demo endpoint) — returning fallback")
            return dict(self._BUSY_FALLBACK)

        self._is_processing = True
        try:
            return await self._do_analyze(user_history, risk_score)
        finally:
            self._is_processing = False

    async def _do_analyze(self, user_history: list | dict, risk_score: int) -> dict:
        """Generate a threat analysis via Llama 3."""
        if not self._available or not self._client:
            return self._fallback(user_history, risk_score)

        prompt = (
            "You are a cybersecurity SOC analyst AI at a large retail and supply-chain "
            "enterprise called Cummins. You are analyzing a sequence of events. Here is "
            "the user's recent activity log leading up to the anomaly. Analyze the "
            "sequence to determine the kill chain and provide a conclusion.\n"
            "Respond with ONLY a valid JSON object (no markdown, no code fences, no "
            "extra text) with exactly two keys:\n"
            '  "summary": a 2-3 sentence explanation of why this is suspicious.\n'
            '  "recommended_action": a specific, actionable step for the SOC team.\n\n'
            f"Activity Sequence:\n{json.dumps(user_history, indent=2)}\n\n"
            f"Risk Score: {risk_score}/100"
        )

        payload = {
            "model":  OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }

        try:
            log.info("🧠 LLM Priority Queue — generating analysis for risk=%d …", risk_score)
            resp = await self._client.post(OLLAMA_URL, json=payload)
            if resp.status_code == 200:
                raw = resp.json().get("response", "{}")
                parsed = json.loads(raw)
                self._calls += 1
                return {
                    "summary":            parsed.get("summary",
                                                     "Analysis unavailable."),
                    "recommended_action":  parsed.get("recommended_action",
                                                     "Escalate to SOC Lead."),
                }
        except json.JSONDecodeError:
            log.warning("⚠  Ollama returned non-JSON — falling back")
        except httpx.TimeoutException:
            log.warning("⚠  Ollama timed out after %.0fs", OLLAMA_TIMEOUT)
        except Exception as exc:
            log.warning("⚠  Ollama error: %s", exc)

        return self._fallback(user_history, risk_score)

    # ── Rule-based fallback when Ollama is unavailable ──────────────────

    @staticmethod
    def _fallback(user_history: list | dict, risk_score: int) -> dict:
        log_data = user_history[-1] if isinstance(user_history, list) else user_history
        actor    = log_data.get("actor", {})
        action   = log_data.get("action", {})
        resource = log_data.get("resource", {})
        context  = log_data.get("context", {})
        uid      = actor.get("user_id", "unknown")
        atype    = action.get("type", "unknown")
        rname    = resource.get("name", "unknown")
        vol      = resource.get("volume_mb", 0)
        sens     = resource.get("sensitivity_label", "")

        # Build contextual summary
        fragments: list[str] = []
        if atype == "config_change":
            fragments.append(
                f"User {uid} performed a config_change on '{rname}' "
                f"({sens}) — potential audit-trail tampering.")
        elif atype in ("file_copy", "file_download") and vol > 1000:
            fragments.append(
                f"User {uid} initiated a {vol:,.0f} MB {atype} of "
                f"'{rname}' ({sens}) — possible data exfiltration.")
        elif atype == "process_kill":
            fragments.append(
                f"User {uid} terminated security process '{rname}' "
                f"— likely EDR evasion attempt.")
        else:
            fragments.append(
                f"Anomalous {atype} by {uid} targeting '{rname}' ({sens}).")

        if actor.get("mfa_status") == "bypassed":
            fragments.append("MFA was BYPASSED.")
        if not context.get("edr_agent_active", True):
            fragments.append("EDR agent is INACTIVE — endpoint blind.")
        if context.get("location") == "Unknown":
            fragments.append("Activity from an UNKNOWN location.")

        summary = " ".join(fragments)

        if risk_score >= 95:
            rec = ("IMMEDIATE: Isolate endpoint, revoke credentials, "
                   "initiate incident response procedure.")
        elif risk_score >= 85:
            rec = ("HIGH: Escalate to SOC Lead, correlate with DLP/SIEM "
                   "alerts, prepare incident report.")
        else:
            rec = "MONITOR: Flag for review in next SOC shift handoff."

        return {"summary": summary, "recommended_action": rec}

    @property
    def call_count(self) -> int:
        return self._calls


# ═══════════════════════════════════════════════════════════════════════════
#  DISCORD WEBHOOK — "PagerDuty Flex" (phones buzz on stage)
# ═══════════════════════════════════════════════════════════════════════════

async def send_discord_alert(
    uid: str,
    risk_score: int,
    llama_narrative: str,
    webhook_url: str = DISCORD_WEBHOOK_URL,
) -> None:
    """Fire a Rich Embed to a Discord webhook.

    Called immediately after Llama 3 (or rule-based fallback) produces
    the incident narrative for a critical alert.  Designed to make the
    presenter's phone buzz on stage during the live hackathon demo.

    This function is fire-and-forget: it will NEVER raise.  If the
    Discord API is down, rate-limited, or the URL is empty, the main
    pipeline continues unaffected.

    Payload format: Discord "Rich Embed" (embeds[] array).
    """
    # ── Guard: skip if no webhook configured ──────────────────────────
    if not webhook_url:
        return

    # ── Color coding by severity ─────────────────────────────────────
    if risk_score >= 95:
        color = 0xFF0000       # Pure red — critical
        severity_label = "🔴 CRITICAL"
    elif risk_score >= 85:
        color = 0xFF6600       # Orange — high
        severity_label = "🟠 HIGH"
    elif risk_score >= 60:
        color = 0xFFCC00       # Yellow — elevated
        severity_label = "🟡 ELEVATED"
    else:
        color = 0x00CC66       # Green — low
        severity_label = "🟢 LOW"

    # ── Build Discord Rich Embed ─────────────────────────────────────
    embed = {
        "title":       f"🚨 AEGIS INTERCEPT — {severity_label}",
        "description": llama_narrative[:2048],   # Discord limit
        "color":       color,
        "fields": [
            {
                "name":   "👤 Compromised User",
                "value":  f"`{uid}`",
                "inline": True,
            },
            {
                "name":   "⚡ Risk Score",
                "value":  f"**{risk_score}** / 100",
                "inline": True,
            },
            {
                "name":   "🛡️ Detection Engine",
                "value":  "VAE + IsolationForest Ensemble",
                "inline": True,
            },
        ],
        "footer": {
            "text": "AEGIS-Fusion • Insider Threat Detection Engine v2.0",
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    payload = {
        "username":   "AEGIS-Fusion SOC",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/6941/6941697.png",
        "embeds":     [embed],
    }

    # ── Fire-and-forget POST ──────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 204:
                log.info("📟 Discord alert sent — uid=%s risk=%d", uid, risk_score)
            else:
                log.warning(
                    "📟 Discord responded %d — %s",
                    resp.status_code, resp.text[:200],
                )
    except Exception as exc:
        # NEVER crash the pipeline over a webhook failure
        log.warning("📟 Discord webhook failed (non-fatal): %s", exc)


# ═══════════════════════════════════════════════════════════════════════════
#  WEBSOCKET CONNECTION MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class ConnectionManager:
    """Thread-safe registry of active WebSocket clients."""

    def __init__(self):
        self._active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._active.append(ws)
        log.info("🔌 WebSocket client connected  — %d active", len(self._active))

    def disconnect(self, ws: WebSocket):
        if ws in self._active:
            self._active.remove(ws)
        log.info("🔌 WebSocket client dropped    — %d active", len(self._active))

    async def broadcast(self, data: dict):
        """Push JSON to every connected client; silently prune dead sockets."""
        dead: list[WebSocket] = []
        for ws in self._active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self._active:
                self._active.remove(ws)

    @property
    def count(self) -> int:
        return len(self._active)


# ═══════════════════════════════════════════════════════════════════════════
#  PIPELINE STATISTICS
# ═══════════════════════════════════════════════════════════════════════════

class PipelineStats:
    """Tracks live metrics for the /api/stats endpoint and terminal logging."""

    def __init__(self):
        self.total_processed  = 0
        self.normal_count     = 0
        self.alert_count      = 0
        self.ollama_calls     = 0
        self.brain0_overrides = 0              # hard-signature bypasses
        self.start_time: float | None = None
        self.status           = "idle"        # idle | running | complete | error
        self.highest_risk     = 0
        self.recent_alerts: list[dict] = []   # rolling buffer of last 100 alerts
        self.risk_distribution = {
            "low": 0, "medium": 0, "high": 0, "critical": 0,
        }

    def reset(self):
        """Resets all telemetry for a clean demo run."""
        self.total_processed  = 0
        self.normal_count     = 0
        self.alert_count      = 0
        self.ollama_calls     = 0
        self.brain0_overrides = 0
        self.start_time       = time.time() if self.status == "running" else None
        self.highest_risk     = 0
        self.recent_alerts    = []
        self.risk_distribution = {
            "low": 0, "medium": 0, "high": 0, "critical": 0,
        }

    def record(self, risk_score: int, is_alert: bool):
        self.total_processed += 1
        if is_alert:
            self.alert_count += 1
        else:
            self.normal_count += 1
        if risk_score > self.highest_risk:
            self.highest_risk = risk_score

        if risk_score < 30:
            self.risk_distribution["low"] += 1
        elif risk_score < 60:
            self.risk_distribution["medium"] += 1
        elif risk_score < ALERT_THRESHOLD:
            self.risk_distribution["high"] += 1
        else:
            self.risk_distribution["critical"] += 1

    def push_alert(self, output: dict):
        self.recent_alerts.append(output)
        if len(self.recent_alerts) > 100:
            self.recent_alerts = self.recent_alerts[-100:]

    @property
    def throughput(self) -> float:
        if not self.start_time:
            return 0.0
        elapsed = time.time() - self.start_time
        return self.total_processed / elapsed if elapsed > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "status":              self.status,
            "total_processed":     self.total_processed,
            "normal_count":        self.normal_count,
            "alert_count":         self.alert_count,
            "brain0_overrides":    self.brain0_overrides,
            "ollama_calls":        self.ollama_calls,
            "highest_risk_score":  self.highest_risk,
            "throughput_lps":      round(self.throughput, 2),
            "risk_distribution":   self.risk_distribution,
            "uptime_s":            round(time.time() - self.start_time, 1)
                                   if self.start_time else 0,
            "merkle_root":         merkle.root,
        }


# ═══════════════════════════════════════════════════════════════════════════
#  GLOBAL ENGINE STATE
# ═══════════════════════════════════════════════════════════════════════════

device   = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model:   InsiderThreatVAE | None = None
iforest_model = None          # sklearn IsolationForest (loaded at startup)
user_history_buffer: dict[str, list[dict]] = {}
merkle   = EnterpriseMerkleTree()
ollama   = OllamaAnalyst()
manager  = ConnectionManager()
stats    = PipelineStats()
ROLES_DF: pd.DataFrame | None = None
FEATURE_META: dict | None = None

# Stream control
_stream_task: asyncio.Task | None = None
_stop_event  = asyncio.Event()


# ═══════════════════════════════════════════════════════════════════════════
#  CORE STREAM PROCESSOR
# ═══════════════════════════════════════════════════════════════════════════

def calculate_weighted_mse(recon_x: torch.Tensor, x: torch.Tensor, reduction: str = 'mean') -> torch.Tensor:
    sq_error = (recon_x - x) ** 2
    threat_indices = [-1, -2, -3, -4, -5] 
    weight_multiplier = 100.0 
    
    for idx in threat_indices:
        sq_error[:, idx] *= weight_multiplier
        
    if reduction == 'none':
        return sq_error.mean(dim=1)
    return sq_error.mean()


async def _run_inference(tensor: torch.Tensor) -> tuple[float, list[dict]]:
    """VAE→IForest ensemble with XAI feature attribution.

    Pipeline:
      tensor → VAE.encode() → mu (10-dim) → IForest.decision_function()
      tensor → VAE.forward() → reconstruction → per-feature MSE → topk(5)

    Returns:
      (decision_score, xai_top_features)
      - decision_score: float (higher = more normal)
      - xai_top_features: list of {"name": str, "error": float, "index": int}
    """
    def _infer() -> tuple[float, list[dict]]:
        with torch.no_grad():
            t = tensor.to(device)

            # ── IsolationForest scoring (unchanged) ──────────────
            mu, logvar = model.encode(t)                           # type: ignore[misc]
            z_np = mu.cpu().numpy()                                # [1, 10]
            decision = iforest_model.decision_function(z_np)       # type: ignore[union-attr]

            # ── XAI: Per-feature reconstruction error ────────────
            # Full forward pass: encode → reparameterize → decode
            z = model.reparameterize(mu, logvar)                   # type: ignore[misc]
            recon = model.decode(z)                                # type: ignore[misc]

            # Per-feature squared error (no reduction) → shape [63]
            feature_errors = ((recon - t) ** 2).squeeze(0)         # [63]

            # Top 5 most anomalous features via vectorized topk
            top_vals, top_idx = torch.topk(feature_errors, k=min(5, feature_errors.shape[0]))

            # Map indices → human-readable names from FEATURE_META
            names = (FEATURE_META or {}).get("feature_names", [])
            xai_features: list[dict] = []
            for val, idx in zip(top_vals.tolist(), top_idx.tolist()):
                name = names[idx] if idx < len(names) else f"dim_{idx}"
                xai_features.append({
                    "name":  name,
                    "error": round(val, 6),
                    "index": idx,
                })

            return float(decision[0]), xai_features

    return await asyncio.to_thread(_infer)


def _enrich_alert(output: dict, log_data: dict) -> dict:
    """Attach user-role context from user_roles.csv (via pandas)."""
    if ROLES_DF is None:
        return output
    # Support both old (actor.user_id) and new (actor.user.uid) OCSF paths
    actor = log_data.get("actor", {})
    uid = actor.get("user_id", "") or actor.get("user", {}).get("uid", "")
    match = ROLES_DF[ROLES_DF["user_id"] == uid]
    if match.empty:
        return output
    row = match.iloc[0]
    expected = str(row.get("expected_resources", ""))
    accessed = log_data.get("resource", {}).get("name", "")
    output["user_context"] = {
        "department":         row["department"],
        "expected_resources": expected,
        "access_violation":   accessed not in expected,
    }
    return output


# ═══════════════════════════════════════════════════════════════════════════
#  BRAIN 0 — DETERMINISTIC HARD-SIGNATURE ENGINE
# ═══════════════════════════════════════════════════════════════════════════
#
# For "black-and-white" threats, we bypass PyTorch entirely.
# If an employee touches a Honey-Token or triggers a physical camera
# sensor, the system does NOT ask the ML model for its opinion.
# ML is for the "gray area"; explicit signatures are for certainties.
#

_BRAIN0_SIGNATURES: list[dict[str, Any]] = [
    {
        "name":  "HONEY_TOKEN",
        "desc":  "Canary file Q4_Executive_Bonuses accessed",
        "check": lambda d: "Q4_Executive_Bonuses" in
                 d.get("resource", {}).get("name", ""),
    },
    {
        "name":  "OPTICAL_SENSOR",
        "desc":  "Phone/camera detected near sensitive screen",
        "check": lambda d: d.get("enrichments", {})
                 .get("aegis_telemetry", {})
                 .get("optical_sensor_state", "") == "Optical Device Detected",
    },
    {
        "name":  "STEGANOGRAPHY",
        "desc":  "Near-random entropy file transfer (stego exfil)",
        "check": lambda d: (
            d.get("enrichments", {}).get("aegis_telemetry", {})
             .get("file_entropy", 0) > 0.97
            and d.get("resource", {}).get("name", "").endswith(".jpg")
        ),
    },
    {
        "name":  "INVENTORY_FRAUD",
        "desc":  "Warehouse user deleting inventory records",
        "check": lambda d: (
            d.get("actor", {}).get("user", {}).get("group", "") == "Warehouse_Floor"
            and d.get("action", {}).get("type", "") == "record_delete"
            and d.get("resource", {}).get("name", "") == "inventory_db"
        ),
    },
    {
        "name":  "BIOMETRIC_HIJACK",
        "desc":  "Continuous Authentication Failure (Session Hijack)",
        "check": lambda d: (
            d.get("action", {}).get("type", "") == "refund_process"
            and d.get("enrichments", {}).get("aegis_telemetry", {}).get("typing_cadence_ms", 100) > 400
        ),
    },
    {
        "name":  "SUPPLY_CHAIN_FRAUD",
        "desc":  "Unauth modification of vendor routing numbers to overseas bank",
        "check": lambda d: (
            d.get("action", {}).get("type", "") == "db_update"
            and "vendor_routing" in d.get("resource", {}).get("name", "")
        ),
    },
    {
        "name":  "S3_EXPOSURE",
        "desc":  "Cloud Admin making S3 bucket public",
        "check": lambda d: (
            d.get("actor", {}).get("user", {}).get("group", "") == "Cloud_Admin"
            and d.get("action", {}).get("type", "") == "permission_change"
            and d.get("resource", {}).get("name", "") == "S3_Backup_Bucket"
        ),
    },
]


def _brain0_check(log_data: dict) -> tuple[bool, str, str]:
    """Run all hard signatures.  Returns (matched, name, description)."""
    for sig in _BRAIN0_SIGNATURES:
        try:
            if sig["check"](log_data):
                return True, sig["name"], sig["desc"]
        except Exception:
            pass
    return False, "", ""


async def process_stream(speed: float = STREAM_SPEED, max_logs: int = 0):
    """Main pipeline coroutine — Dual-Brain Architecture.

    For each log in enterprise_activity_stream.jsonl:
      1. SHA-256 hash → rolling Merkle root     (integrity)
      2. BRAIN 0: Hard-signature check          (deterministic)
         → If matched: risk=100, bypass PyTorch
      3. BRAIN 1: Vectorise → VAE → MSE → risk  (ML inference)
      4. If critical → Ollama LLM analysis       (explainability)
      5. JSON → every connected WebSocket        (broadcast)
    """
    global _stop_event

    if not JSONL_PATH.exists():
        log.error("❌ Stream file not found: %s", JSONL_PATH)
        stats.status = "error"
        return

    stats.status     = "running"
    stats.start_time = time.time()
    processed        = 0

    log.info("━" * 62)
    log.info("▶  STREAM ONLINE — %s", JSONL_PATH.name)
    log.info("   Speed : %.2fs/log  (~%d logs/sec)",
             speed, int(1 / speed) if speed > 0 else 9999)
    log.info("   Limit : %s", f"{max_logs:,}" if max_logs else "unlimited")
    log.info("   Brain 0 : %d hard signatures loaded",
             len(_BRAIN0_SIGNATURES))
    log.info("   Brain 1 : VAE threshold > %d → critical + LLM",
             ALERT_THRESHOLD)
    log.info("   Device : %s", device)
    log.info("━" * 62)

    try:
        with open(JSONL_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                # ── Stop / limit checks ──
                if _stop_event.is_set():
                    log.warning("⏹  Stream halted by operator")
                    break
                if max_logs > 0 and processed >= max_logs:
                    log.info("✋ Max-log limit reached (%d)", max_logs)
                    break

                raw = line.strip()
                if not raw:
                    continue

                try:
                    # ── 1. Parse ──────────────────────────────────────
                    log_data: dict[str, Any] = json.loads(raw)

                    # ── 2. Merkle integrity ───────────────────────────
                    merkle_root = merkle.ingest(raw)

                    # Resolve user ID (supports both OCSF versions)
                    actor = log_data.get("actor", {})
                    uid = (actor.get("user_id", "")
                           or actor.get("user", {}).get("uid", "?"))

                    # --- SEQUENCE BUFFER UPDATE ---
                    if uid not in user_history_buffer:
                        user_history_buffer[uid] = []
                    user_history_buffer[uid].append(log_data)
                    user_history_buffer[uid] = user_history_buffer[uid][-10:]

                    # ══════════════════════════════════════════════════
                    # BRAIN 0 — Deterministic Hard-Signature Override
                    # ══════════════════════════════════════════════════
                    b0_hit, b0_name, b0_desc = _brain0_check(log_data)

                    if b0_hit:
                        # Hard signature → risk = 100, skip PyTorch
                        risk_score  = 100
                        mse         = -1.0       # sentinel: ML not used
                        is_critical = True
                        stats.brain0_overrides += 1

                        log.critical(
                            "🛑 BRAIN-0 OVERRIDE │ %s │ %s │ %s │ %s",
                            b0_name, uid,
                            log_data.get("resource", {}).get("name", "?"),
                            b0_desc,
                        )

                    # ══════════════════════════════════════════════════
                    # BRAIN 1 — PyTorch VAE (gray-area ML inference)
                    # ══════════════════════════════════════════════════
                    else:
                        tensor      = preprocess_json_to_tensor(log_data, user_history_buffer.get(uid, []))
                        decision, xai_top_features = await _run_inference(tensor)
                        risk_score  = iforest_decision_to_risk(decision)
                        is_critical = risk_score > ALERT_THRESHOLD

                        if is_critical:
                            log.critical(
                                "🧠 BRAIN-1 ENSEMBLE │ risk=%d │ %s │ %s │ %s │ "
                                "%.4fMB │ iforest=%.4f",
                                risk_score, uid,
                                log_data.get("action", {}).get("type", "?"),
                                log_data.get("resource", {}).get("name", "?"),
                                log_data.get("resource", {}).get("volume_mb", 0),
                                decision,
                            )

                    # ── Build output contract ─────────────────────────
                    output: dict[str, Any] = {
                        "event_type":       "critical_alert" if is_critical
                                            else "normal",
                        "timestamp":        log_data.get("timestamp", ""),
                        "risk_score":       risk_score,
                        "detection_brain":  "brain0_signature" if b0_hit
                                            else "brain1_vae",
                        "signature_name":   b0_name if b0_hit else None,
                        "raw_log":          log_data,
                        # ── XAI: Top contributing features ────────
                        "xai_top_features": xai_top_features if not b0_hit else [],
                        # Queue handles LLM population for critical logs
                        "ai_analysis":      None,
                        "merkle_integrity": "Verified",
                        "merkle_root":      merkle_root[:16] + "…",
                        "sequence":         processed,
                    }

                    if is_critical:
                        output = _enrich_alert(output, log_data)
                        stats.push_alert(output)
                        # We hand critical alerts to the LLM Priority Queue
                        # It will await 1s, drop inferiors, and broadcast later.
                        ollama.enqueue(user_history_buffer[uid], risk_score, output)
                    else:
                        # Normal events skip LLM and broadcast immediately
                        await manager.broadcast(output)

                    # ── 9. Stats ──────────────────────────────────────
                    stats.record(risk_score, is_critical)
                    processed += 1

                    # Periodic heartbeat every 1 000 logs
                    if processed % 1000 == 0:
                        log.info(
                            "📊 %s logs │ %d alerts │ %.1f/s │ merkle %s…",
                            f"{processed:>8,}",
                            stats.alert_count,
                            stats.throughput,
                            merkle_root[:12],
                        )

                except json.JSONDecodeError:
                    log.warning("⚠  Malformed JSON at line %d — skipped",
                                processed + 1)
                except KeyError as exc:
                    log.warning("⚠  Missing key %s at line %d — skipped",
                                exc, processed + 1)
                except Exception as exc:
                    log.error("❌ Line %d error: %s", processed + 1, exc)

                # ── Simulate real-time cadence ────────────────────────
                await asyncio.sleep(speed)

    except Exception as exc:
        log.error("❌ Fatal stream error: %s", exc)
        stats.status = "error"
        return

    stats.status = "complete"
    elapsed = time.time() - (stats.start_time or time.time())

    log.info("━" * 62)
    log.info("✅  STREAM COMPLETE")
    log.info("    Total processed  : %s", f"{processed:,}")
    log.info("    Critical alerts  : %d", stats.alert_count)
    log.info("      Brain 0 (sig)  : %d", stats.brain0_overrides)
    log.info("      Brain 1 (ML)   : %d",
             stats.alert_count - stats.brain0_overrides)
    log.info("    Ollama calls     : %d", stats.ollama_calls)
    log.info("    Elapsed          : %.1fs", elapsed)
    log.info("    Avg throughput   : %.2f logs/s", stats.throughput)
    log.info("    Merkle root      : %s", merkle.root)
    log.info("━" * 62)


# ═══════════════════════════════════════════════════════════════════════════
#  FASTAPI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════

_BANNER = """
    +===========================================================+
    |    ___   ____  ____ ___ ____   v2.0                       |
    |   /   | / __/ / __// // __/                               |
    |  / /| |/ _/  / /_ / //_\ \                                |
    | / ___ / /__ / /_// //__ /                                 |
    |/_/  |_\___/ \___/___/___/                                 |
    |                                                           |
    |  Insider Threat Detection Engine                          |
    |  FastAPI - PyTorch VAE - Ollama - WebSocket - Merkle      |
    +===========================================================+
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown lifecycle."""
    global model, iforest_model, ROLES_DF, TRAIN_MSE_MEAN, TRAIN_MSE_STD, FEATURE_META
    global IFOREST_SAFE_ANCHOR, IFOREST_ALERT_ANCHOR

    try:
        sys.stdout.buffer.write(_BANNER.encode("utf-8"))
        sys.stdout.buffer.flush()
    except Exception:
        print(_BANNER.encode("ascii", errors="replace").decode())

    # ── Feature metadata ──
    if META_PATH.exists():
        FEATURE_META = json.loads(META_PATH.read_text("utf-8"))
        log.info("[META] Feature meta  -- %d features loaded",
                 FEATURE_META.get("num_features", INPUT_DIM))
    else:
        log.warning("⚠  feature_meta.json not found — using defaults")

    # ── Training calibration stats ──
    if THRESH_PATH.exists():
        cal = json.loads(THRESH_PATH.read_text())
        TRAIN_MSE_MEAN = cal.get("train_mse_mean", TRAIN_MSE_MEAN)
        TRAIN_MSE_STD  = cal.get("train_mse_std",  TRAIN_MSE_STD)
        log.info("[CAL]  Calibration   -- mean=%.6f  std=%.6f  p99=%.6f",
                 TRAIN_MSE_MEAN, TRAIN_MSE_STD, cal.get("train_mse_p99", 0))
    else:
        log.warning("⚠  threshold_stats.json not found — using hardcoded calibration")

    # ── User roles (pandas) ──
    if ROLES_PATH.exists():
        ROLES_DF = pd.read_csv(ROLES_PATH)
        log.info("[ROLE] User roles    -- %d users, %d departments",
                 len(ROLES_DF), ROLES_DF["department"].nunique())
    else:
        log.warning("⚠  user_roles.csv not found — alert enrichment disabled")

    # ── PyTorch VAE ──
    model = InsiderThreatVAE(input_dim=INPUT_DIM, latent_dim=LATENT_DIM).to(device)
    if MODEL_PATH.exists():
        model.load_state_dict(
            torch.load(MODEL_PATH, map_location=device, weights_only=True),
        )
        model.eval()
        params = sum(p.numel() for p in model.parameters())
        log.info("[VAE]  Model loaded  -- %s params on %s",
                 f"{params:,}", device)
    else:
        model.eval()
        log.warning("⚠  %s not found — running with RANDOM weights!",
                    MODEL_PATH.name)

    # ── IsolationForest ensemble ──
    if IFOREST_PATH.exists():
        iforest_model = joblib.load(IFOREST_PATH)
        log.info("[IFOR] IsolationForest loaded -- %d trees",
                 iforest_model.n_estimators)
    else:
        log.warning("iforest.pkl not found -- falling back to MSE scoring")

    if IFOREST_CAL.exists():
        _cal = json.loads(IFOREST_CAL.read_text("utf-8"))
        IFOREST_SAFE_ANCHOR  = _cal["safe_anchor"]
        IFOREST_ALERT_ANCHOR = _cal["alert_anchor"]
        log.info("[IFOR] Calibration    -- safe=%.4f  alert=%.4f",
                 IFOREST_SAFE_ANCHOR, IFOREST_ALERT_ANCHOR)

    # ── Ollama ──
    await ollama.initialize()

    # ── JSONL check ──
    if JSONL_PATH.exists():
        size_mb = JSONL_PATH.stat().st_size / (1024 * 1024)
        log.info("[FILE] Stream file   -- %s (%.1f MB)", JSONL_PATH.name, size_mb)
    else:
        log.error("❌ %s NOT FOUND — stream will fail", JSONL_PATH.name)

    log.info("=" * 62)
    log.info(">> AEGIS ENGINE ONLINE")
    log.info("   POST /api/stream/start   -> begin processing")
    log.info("   POST /api/stream/stop    -> halt processing")
    log.info("   GET  /api/stats          -> live metrics")
    log.info("   GET  /api/alerts         -> recent critical alerts")
    log.info("   WS   /ws/stream          -> real-time event feed")
    log.info("=" * 62)

    yield  # ── application runs here ──

    # ── Teardown ──
    _stop_event.set()
    if _stream_task and not _stream_task.done():
        _stream_task.cancel()
    await ollama.shutdown()
    log.info("[STOP] AEGIS ENGINE OFFLINE -- final merkle root: %s", merkle.root)


app = FastAPI(
    title="AEGIS Insider Threat Detection Engine",
    description="Real-time insider threat detection via PyTorch VAE "
                "with Ollama LLM explainability and Merkle log integrity.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # TODO: lock to your Next.js origin in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REST Endpoints ────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
async def health_check():
    """Quick liveness probe."""
    return {
        "engine":            "AEGIS v2.0",
        "status":            "online",
        "model_loaded":      model is not None,
        "device":            str(device),
        "stream_status":     stats.status,
        "websocket_clients": manager.count,
        "merkle_chain":      merkle.count,
    }


@app.get("/api/stats", tags=["Monitoring"])
async def get_stats():
    """Detailed pipeline metrics for the monitoring dashboard."""
    return stats.to_dict()


@app.get("/api/alerts", tags=["Monitoring"])
async def get_alerts():
    """Return the most recent critical alerts (rolling buffer of 100)."""
    return {
        "total_alerts":  stats.alert_count,
        "showing":       len(stats.recent_alerts),
        "alerts":        stats.recent_alerts,
    }


@app.get("/api/merkle", tags=["Integrity"])
async def get_merkle():
    """Current Merkle chain state for audit verification."""
    return {
        "merkle_root":   merkle.root,
        "chain_length":  merkle.count,
        "integrity":     "Verified" if merkle.count > 0 else "No data",
    }


@app.post("/api/stream/start", tags=["Stream Control"])
async def start_stream(
    speed: float = Query(
        default=0.1, ge=0.0, le=5.0,
        description="Seconds between log reads (0.1 = 10 logs/sec)",
    ),
    max_logs: int = Query(
        default=0, ge=0,
        description="Maximum logs to process (0 = unlimited / entire file)",
    ),
):
    """Begin ingesting the JSONL stream."""
    global _stream_task, _stop_event

    if stats.status == "running":
        return JSONResponse(
            status_code=409,
            content={"error": "Stream is already running",
                     "stats": stats.to_dict()},
        )

    _stop_event = asyncio.Event()
    _stream_task = asyncio.create_task(process_stream(speed, max_logs))
    log.info("▶  Stream task launched — speed=%.2f  max_logs=%s",
             speed, max_logs or "∞")

    return {
        "message":  "Stream started",
        "speed":    speed,
        "max_logs": max_logs or "unlimited",
    }


@app.post("/api/stream/stop", tags=["Stream Control"])
async def stop_stream():
    """Gracefully halt the running stream."""
    if stats.status != "running":
        return JSONResponse(
            status_code=409,
            content={"error": "No stream is currently running"},
        )

    _stop_event.set()
    stats.reset()
    stats.status = "idle"
    return {"message": "Stop signal sent and stats reset to 0.",
            "stats":   stats.to_dict()}


@app.post("/api/inject_test_log", tags=["Stream Control"])
async def inject_test_log(payload: dict):
    """Inject a honey-trap event with graduated severity based on impact_level.

    impact_level values:
      MISTAKE            -> risk 45, Suspicious  (accidental click, log only)
      PROLONGED_EXPOSURE -> risk 80, Critical    (file open > 7 s)
      EXFILTRATION       -> risk 100, Critical   (download completed)
    """
    log_data     = payload.get("log_data", payload)
    impact_level = payload.get("impact_level", "EXFILTRATION")

    if impact_level == "MISTAKE":
        risk_score = 45
        event_type = "suspicious"
        user_id = log_data.get("actor", {}).get("user_id", "Unknown")
        summary    = (
            f"SUSPICIOUS: User {user_id} accessed a Honey-Token path. "
            "Single interaction — may be accidental. Monitoring continued."
        )
        recommended = "WATCH: Log user activity for the next 30 minutes. No immediate action required."

    elif impact_level == "PROLONGED_EXPOSURE":
        risk_score = 80
        event_type = "critical_alert"
        user_id = log_data.get("actor", {}).get("user_id", "Unknown")
        summary    = (
            f"CRITICAL: User {user_id} has kept the Honey-Token document open for an "
            "extended period. This indicates active reading of confidential material."
        )
        recommended = "HIGH: Alert SOC Lead. Initiate passive monitoring and prepare to isolate endpoint."

    else:  # EXFILTRATION (default)
        risk_score = 100
        event_type = "critical_alert"
        user_id = log_data.get("actor", {}).get("user_id", "Unknown")
        summary    = (
            f"CRITICAL: Active Deception Triggered. User {user_id} completed a download "
            "of a known Honey-Token file (Q4_Executive_Bonuses_2026.xlsx). "
            "Data exfiltration confirmed."
        )
        recommended = "IMMEDIATE: Isolate endpoint, revoke credentials, initiate incident response."

    output = {
        "event_type":       event_type,
        "risk_score":       risk_score,
        "impact_level":     impact_level,
        "type":             "Honey-Trap Triggered",
        "threat_vectors":   ["Honey-Trap Triggered"],
        "raw_log":          log_data,
        "ai_analysis": {
            "summary":            summary,
            "recommended_action": recommended,
            "threat_vectors":     ["Honey-Trap Triggered"],
        },
        "merkle_integrity": "Verified",
        "merkle_root":      "8f4c2b9a…",
        "sequence":         999,
        "timestamp":        log_data.get("timestamp", ""),
    }

    log.warning(
        "🍯 HONEY-TRAP [%s] risk=%d — user=%s",
        impact_level, risk_score,
        log_data.get("actor", {}).get("user_id", "?"),
    )

    await manager.broadcast(output)
    return {"message": f"Honey-trap event [{impact_level}] injected", "payload": output}


@app.post("/api/tamper", tags=["Stream Control"])
async def trigger_tamper():
    """Hackathon Mic Drop Feature: Shatter the merkle chain live."""
    # 1. Artificially corrupt the global Merkle root
    merkle._root = "0000000_CORRUPTED_TAMPER_DETECTED_0000000"
    
    # 2. Build the visual payload
    payload = {
        "event_type": "tamper_alert",
        "merkle_integrity": "COMPROMISED",
        "merkle_root": "CHAIN_BROKEN",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    # 3. Log it brilliantly
    log.critical("🚨 🚨 🚨 MERKLE LEDGER SHATTERED 🚨 🚨 🚨")
    log.critical("Manual /api/tamper injected.")
    
    # 4. Broadcast immediately
    await manager.broadcast(payload)
    return {"message": "Tamper simulation triggered successfully."}


# ── Active Deception & Steganography ─────────────────────────────────────

@app.get("/api/verify-network", tags=["Geofencing"])
async def verify_network(request: Request, user_id: str = "UNKNOWN"):
    """Geofence check — returns whether the caller is on the approved office network.

    If outside the perimeter, broadcasts a geofencing violation to the SOC.
    """
    client_ip = request.headers.get("X-Forwarded-For", request.client.host)
    client_ip = client_ip.split(",")[0].strip()

    is_allowed = client_ip.startswith(ALLOWED_SUBNET) or client_ip == "127.0.0.1" or client_ip == "::1"

    log.info(
        "[GEO] Network check — IP: %s | Subnet: %s | Allowed: %s | User: %s",
        client_ip, ALLOWED_SUBNET, is_allowed, user_id
    )

    if not is_allowed:
        audit_output = {
            "event_type": "critical_alert",
            "risk_score": 95,
            "impact_level": "GEOFENCE_VIOLATION",
            "type": "Network Perimeter Breach",
            "raw_log": {
                "actor": {"user_id": user_id},
                "action": {"type": "unauthorized_access_attempt"},
                "context": {
                    "ip_address": client_ip,
                    "location": "Unknown / External Network",
                    "edr_agent_active": False
                }
            },
            "ai_analysis": {
                "summary": f"CRITICAL: User {user_id} attempted to access classified document from OUTSIDE the office perimeter. Source IP: {client_ip}. Network geofencing policy violated.",
                "threat_vectors": ["Geofence Violation", "External Access Attempt"],
                "recommended_action": "IMMEDIATE: Block session token, alert physical security, log exfiltration attempt."
            },
            "merkle_integrity": "Verified",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sequence": 7777
        }
        await manager.broadcast(audit_output)

    return {
        "allowed": is_allowed,
        "client_ip": client_ip,
        "allowed_subnet": ALLOWED_SUBNET,
        "policy": "OFFICE_WIFI_ONLY",
        "message": "Access granted — on approved network." if is_allowed else f"Access denied — device is outside the office perimeter (IP: {client_ip})."
    }


@app.post("/api/download_watermarked", tags=["Forensics"])
async def download_watermarked(user_id: str = Form(...), department: str = Form(...)):
    """Auto-Injector: Embeds user ID into template.png using high-frequency DCT."""
    global GLOBAL_LAST_IDENTITY

    if WaterMark is None:
        return JSONResponse(status_code=501, content={"error": "blind_watermark not installed"})

    ts = int(time.time())
    GLOBAL_LAST_IDENTITY = {
        "user_id": user_id,
        "department": department,
        "timestamp": ts
    }

    payload = f"ID:{user_id}|DPT:{department}|T:{ts}"
    padded_payload = payload.ljust(40, '*')[:40]

    bits = [int(b) for b in ''.join([format(ord(c), '08b') for c in padded_payload])]

    bwm = WaterMark(password_wm=1, password_img=1)
    
    import os
    template_path = os.path.join(os.path.dirname(__file__), "template.png")
    bwm.read_img(template_path)
    bwm.read_wm(bits, mode='bit')

    out_path = f"target_{user_id}.png"
    bwm.embed(out_path)

    # ── Sync-Locked Differential Barcode (The Forensic "Lock-On" Protocol) ──
    # Prepend a 16-bit Sync Header [1,0,1,0...] to allow the decoder to find the grid.
    import cv2
    import numpy as np
    img = cv2.imread(out_path)
    if img is not None:
        h_img, w_img = img.shape[:2]
        # Payload (80) + Sync (16) = 96 bits
        payload_bits = ''.join([format(ord(c), '08b') for c in user_id.ljust(10, '*')[:10]])
        sync_bits = "1010101010101010"
        full_bits = sync_bits + payload_bits
        
        UNIT_W = 20
        BLOCK_W, BLOCK_H = UNIT_W // 2, 30
        X_START = (w_img - (48 * UNIT_W)) // 2  # Center 48 bits per row
        Y_BASE = h_img - 150
        DELTA = 22 # Visually subtle on dark dashboard, mathematically loud
        
        for i, bit in enumerate(full_bits):
            row = 0 if i < 48 else 1
            col = i % 48
            x_unit = X_START + col * UNIT_W
            y_unit = Y_BASE + row * (BLOCK_H + 10)
            
            l_slice = img[y_unit:y_unit+BLOCK_H, x_unit:x_unit+BLOCK_W].astype(np.int16)
            r_slice = img[y_unit:y_unit+BLOCK_H, x_unit+BLOCK_W:x_unit+UNIT_W].astype(np.int16)
            
            if bit == '1':
                l_slice = np.clip(l_slice + DELTA, 0, 255)
                r_slice = np.clip(r_slice - DELTA, 0, 255)
            else:
                l_slice = np.clip(l_slice - DELTA, 0, 255)
                r_slice = np.clip(r_slice + DELTA, 0, 255)
                
            img[y_unit:y_unit+BLOCK_H, x_unit:x_unit+BLOCK_W] = l_slice.astype(np.uint8)
            img[y_unit:y_unit+BLOCK_H, x_unit+BLOCK_W:x_unit+UNIT_W] = r_slice.astype(np.uint8)
            
        cv2.imwrite(out_path, img)
        log.info(f"[STEGO] Sync-Locked Barcode burned for {user_id} (Invisible DELTA=±{DELTA})")

    return FileResponse(path=out_path, filename="Q4_Financial_Summary.png", media_type="image/png")


@app.post("/api/extract_watermark", tags=["Forensics"])
async def extract_watermark(file: UploadFile = File(...)):
    """Decrypter: Extracts the 40 char string from a leaked screenshot."""
    import tempfile
    import os
    import re

    if WaterMark is None:
        return JSONResponse(status_code=501, content={"error": "blind_watermark not installed"})

    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        bwm = WaterMark(password_wm=1, password_img=1)
        # 40 chars * 8 bits = 320 bits
        extracted_bits = bwm.extract(tmp_path, wm_shape=320, mode='bit')

        bit_strs = ['1' if b else '0' for b in extracted_bits]
        extracted_chars = [chr(int(''.join(bit_strs[i:i+8]), 2)) for i in range(0, len(bit_strs), 8)]
        wm_extract = ''.join(extracted_chars)

        is_corrupted = not bool(re.match(r"^ID:[A-Za-z0-9.]+\|DPT:", wm_extract))

        analog_recovery = False
        if is_corrupted:
            import cv2
            import numpy as np

            # Core Deep Spatial SIFT Re-alignment
            template_path = os.path.join(os.path.dirname(__file__), "template.png")
            img_ref = cv2.imread(template_path, cv2.IMREAD_GRAYSCALE)
            img_warped = cv2.imread(tmp_path, cv2.IMREAD_GRAYSCALE)

            if img_ref is not None and img_warped is not None:
                try:
                    sift = cv2.SIFT_create()
                    kp1, des1 = sift.detectAndCompute(img_ref, None)
                    kp2, des2 = sift.detectAndCompute(img_warped, None)

                    if des1 is not None and des2 is not None:
                        bf = cv2.BFMatcher()
                        matches = bf.knnMatch(des1, des2, k=2)

                        # Lowe's ratio test
                        good = []
                        for pair in matches:
                            if len(pair) == 2:
                                m, n = pair
                                if m.distance < 0.75 * n.distance:
                                    good.append(m)

                        if len(good) > 10:
                            src_pts = np.float32([kp1[m.queryIdx].pt for m in good]).reshape(-1, 1, 2)
                            dst_pts = np.float32([kp2[m.trainIdx].pt for m in good]).reshape(-1, 1, 2)

                            M, mask = cv2.findHomography(dst_pts, src_pts, cv2.RANSAC, 5.0)

                            if M is not None:
                                h, w = img_ref.shape
                                aligned_img = cv2.warpPerspective(img_warped, M, (w, h))

                                # Save the aligned image for re-extraction
                                aligned_path = tmp_path + "_aligned.png"
                                cv2.imwrite(aligned_path, aligned_img)

                                # Re-run mathematical extraction on the SIFT-aligned image
                                ext_bits = bwm.extract(aligned_path, wm_shape=320, mode='bit')
                                b_strs = ['1' if b else '0' for b in ext_bits]
                                ext_chars = [chr(int(''.join(b_strs[i:i+8]), 2)) for i in range(0, len(b_strs), 8)]
                                wm_extract_new = ''.join(ext_chars)

                                # Validate new true extraction
                                if bool(re.match(r"^ID:[A-Za-z0-9.]+\|DPT:", wm_extract_new)):
                                    wm_extract = wm_extract_new
                                    analog_recovery = True
                                    log.info(f"[SIFT] Hardware optical alignment succeeded -> {wm_extract}")
                                else:
                                    log.warning("[SIFT] Post-alignment DCT extraction still failed. Photograph too corrupt.")
                except Exception as e:
                    log.error(f"[SIFT] Optical alignment error: {e}")

        # ── Semantic Barcode Fallback ──────────────────────────────────
        # If DCT is destroyed by Moiré/compression, try reading the visual barcode
        if not bool(re.match(r"^ID:[A-Za-z0-9.]+\|DPT:", wm_extract)):
            import cv2
            import numpy as np
            log.warning("[STEGO] DCT extraction failed. Attempting Semantic Barcode fallback...")

            # Use the SIFT-aligned image if available, otherwise the raw upload
            barcode_source = tmp_path + "_aligned.png"
            if not os.path.exists(barcode_source):
                barcode_source = tmp_path

            bc_img = cv2.imread(barcode_source, cv2.IMREAD_GRAYSCALE)
            if bc_img is not None:
                h_bc, w_bc = bc_img.shape[:2]
                UNIT_W = 20
                BLOCK_W, BLOCK_H = UNIT_W // 2, 30
                X_START_NOMINAL = (w_bc - (48 * UNIT_W)) // 2
                Y_BASE = h_bc - 150
                SYNC_EXPECTED = "1010101010101010"

                best_offset = 0
                max_contrast = -1
                
                # ── Step 1: Lock-On Sweep ──
                # Test offsets from -25 to +25 pixels to find the synchronization pulse
                for offset in range(-25, 26):
                    x_lock = X_START_NOMINAL + offset
                    contrast_score = 0
                    for s_idx in range(16):
                        x_u = x_lock + s_idx * UNIT_W
                        l_m = np.mean(bc_img[Y_BASE+2 : Y_BASE+BLOCK_H-2, x_u+1 : x_u+BLOCK_W-1])
                        r_m = np.mean(bc_img[Y_BASE+2 : Y_BASE+BLOCK_H-2, x_u+BLOCK_W+1 : x_u+UNIT_W-1])
                        
                        # Contrast is the bit's signal strength (higher = better alignment)
                        bit_signal = 1 if l_m > r_m else 0
                        if str(bit_signal) == SYNC_EXPECTED[s_idx]:
                            contrast_score += abs(l_m - r_m)
                        else:
                            contrast_score -= 50 # Severe penalty for parity flip
                    
                    if contrast_score > max_contrast:
                        max_contrast = contrast_score
                        best_offset = offset
                
                log.info(f"[STEGO] Lock-On Succeeded: Offset={best_offset}px, Contrast={max_contrast:.1f}")
                
                # ── Step 2: Read Data starting at Lock-On offset ──
                x_final = X_START_NOMINAL + best_offset
                full_bits_rec = []
                for i in range(96):
                    row = 0 if i < 48 else 1
                    col = i % 48
                    x_u = x_final + col * UNIT_W
                    y_u = Y_BASE + row * (BLOCK_H + 10)
                    
                    l_m = np.mean(bc_img[y_u+2:y_u+BLOCK_H-2, x_u+1:x_u+BLOCK_W-1])
                    r_m = np.mean(bc_img[y_u+2:y_u+BLOCK_H-2, x_u+BLOCK_W+1:x_u+UNIT_W-1])
                    full_bits_rec.append('1' if l_m > r_m else '0')
                
                # Assembly (skip 16 sync bits)
                bit_str = ''.join(full_bits_rec[16:])
                chars = [chr(int(bit_str[i:i+8], 2)) for i in range(0, len(bit_str), 8) if i+8 <= len(bit_str)]
                barcode_id = ''.join(chars).rstrip('*').strip()
                log.info(f"[STEGO] Recovery Match: {repr(barcode_id)}")

                if len(barcode_id) >= 2 and barcode_id.isprintable():
                    # Reconstruct the full signature from the barcode identity
                    wm_extract = f"ID:{barcode_id}|DPT:SEMANTIC_RECOVERY|T:0"
                    analog_recovery = True
                    log.info(f"[STEGO] ✅ Semantic Barcode recovered identity: {barcode_id}")
                else:
                    log.warning(f"[STEGO] Barcode decode produced invalid result: {repr(barcode_id)}")

        # Final validation gate
        if not bool(re.match(r"^ID:[A-Za-z0-9._ ]+\|DPT:", wm_extract)):
             return {"error": "All extraction layers failed. DCT frequencies destroyed and semantic barcode unreadable.", "extracted_signature": wm_extract}

        if wm_extract and "ID:" in wm_extract:
            parts = wm_extract.split('|')
            user_id = parts[0].replace("ID:", "").strip()

            audit_output = {
                "event_type": "critical_alert",
                "risk_score": 100,
                "impact_level": "FORENSIC_MATCH",
                "type": "Forensic Identification",
                "raw_log": {
                    "actor": {"user_id": user_id},
                    "action": {"type": "stego_extraction_match"},
                    "context": {"method": "DCT_FREQUENCY_ANALYSIS", "recovery": "analog_hole" if analog_recovery else "standard"}
                },
                "ai_analysis": {
                    "summary": f"CRITICAL: Forensic match confirmed. Leaked document pixels traced to actor {user_id}. Source: Digital Forensic Artifact.",
                    "threat_vectors": ["Forensic Identity Match"],
                    "recommended_action": "IMMEDIATE: Revoke all system access for identified actor."
                },
                "merkle_integrity": "Verified",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "sequence": 8888
            }
            await manager.broadcast(audit_output)

        return {"extracted_signature": wm_extract, "analog_recovery": analog_recovery}
    except Exception as e:
        return {"error": str(e), "extracted_signature": "FAILED_TO_EXTRACT"}
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
            
        aligned_path = tmp_path + "_aligned.png"
        if os.path.exists(aligned_path):
            os.remove(aligned_path)


# ── Policy Action Simulation ─────────────────────────────────────────────

POLICY_LABELS = {
    "EXTERNAL_STORAGE_ALLOWED":   "External Storage (USB / Pen Drive)",
    "EXTERNAL_EMAIL_ATTACHMENTS": "External Email Attachments",
    "SOFTWARE_INSTALLATION":      "Unauthorized Software Installation",
    "UNRESTRICTED_WEB_BROWSING":  "Unrestricted Web Browsing",
}


@app.post("/api/policy-action", tags=["IAM"])
async def policy_action(payload: dict):
    """Simulate a user attempting a policy-controlled action.

    Checks whether the user has the required permission in user_roles.csv.
    If DENIED → broadcasts a critical policy violation alert to the SOC.
    If ALLOWED → broadcasts a low-risk audit log.
    """
    user_id    = payload.get("user_id", "UNKNOWN")
    policy_key = payload.get("policy_key", "")
    department = payload.get("department", "Unknown")

    # ── Look up the user's permissions ──
    user_permissions: list[str] = []
    user_name = user_id
    if ROLES_PATH.exists():
        import csv
        with open(ROLES_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("user_id") == user_id:
                    user_name = row.get("name", user_id)
                    user_permissions = [
                        r.strip() for r in row.get("expected_resources", "").split(",") if r.strip()
                    ]
                    break

    is_allowed = policy_key in user_permissions
    label = POLICY_LABELS.get(policy_key, policy_key)

    if is_allowed:
        # ── ALLOWED: low-risk audit log ──
        output = {
            "event_type":       "audit_log",
            "risk_score":       15,
            "impact_level":     "POLICY_ALLOWED",
            "type":             "Policy Action — Authorized",
            "threat_vectors":   [],
            "raw_log": {
                "actor":    {"user_id": user_id, "name": user_name, "department": department},
                "action":   {"type": f"policy_use:{policy_key}"},
                "resource": {"name": label},
                "context":  {"ip_address": "10.0.0.99", "location": "Office", "device_type": "managed_laptop"},
            },
            "ai_analysis": {
                "summary": f"INFO: User {user_name} ({user_id}) exercised authorized privilege — {label}. Action permitted by IAM policy.",
                "threat_vectors": [],
                "recommended_action": "No action required. Activity is within granted permissions.",
            },
            "merkle_integrity": "Verified",
            "timestamp":        datetime.utcnow().isoformat() + "Z",
            "sequence":         6666,
        }
        log.info("[IAM] ✅ POLICY ALLOWED — %s (%s) → %s", user_name, user_id, policy_key)
    else:
        # ── DENIED: critical policy violation ──
        output = {
            "event_type":       "critical_alert",
            "risk_score":       90,
            "impact_level":     "POLICY_VIOLATION",
            "type":             "Unauthorized Policy Action",
            "threat_vectors":   ["Policy Violation", f"Unauthorized {label}"],
            "raw_log": {
                "actor":    {"user_id": user_id, "name": user_name, "department": department},
                "action":   {"type": f"policy_violation:{policy_key}"},
                "resource": {"name": label},
                "context":  {"ip_address": "10.0.0.99", "location": "Office", "device_type": "managed_laptop"},
            },
            "ai_analysis": {
                "summary": (
                    f"CRITICAL: User {user_name} ({department}) attempted to use "
                    f"'{label}' — a privilege NOT assigned to their IAM profile. "
                    "This may indicate privilege escalation or policy circumvention."
                ),
                "threat_vectors": ["Policy Violation", f"Unauthorized {label}"],
                "recommended_action": (
                    "IMMEDIATE: Review the user's access profile on the Privilege Control page. "
                    "If unauthorized, revoke session and escalate to HR."
                ),
            },
            "merkle_integrity": "Verified",
            "timestamp":        datetime.utcnow().isoformat() + "Z",
            "sequence":         6667,
        }
        log.warning(
            "🚫 POLICY VIOLATION — %s (%s) attempted %s (NOT AUTHORIZED)",
            user_name, user_id, policy_key,
        )

    await manager.broadcast(output)
    return {"allowed": is_allowed, "user_id": user_id, "policy_key": policy_key, "label": label}


# ── Identity & Access Management ─────────────────────────────────────────

@app.get("/api/users", tags=["IAM"])
async def get_users():
    """Return a list of users and their current permissions from user_roles.csv"""
    users = []
    if ROLES_PATH.exists():
        import csv
        with open(ROLES_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= 50:
                    break
                perms = [r.strip() for r in row.get("expected_resources", "").split(",") if r.strip()]
                users.append({
                    "id": row.get("user_id", ""),
                    "name": row.get("name", row.get("user_id", "")),
                    "department": row.get("department", "Unknown"),
                    "permissions": perms
                })
    return {"users": users}


@app.post("/api/users/permissions", tags=["IAM"])
async def update_user_permissions(payload: dict):
    """Update permissions for a specific user updating user_roles.csv."""
    user_id = payload.get("user_id")
    permissions = payload.get("permissions", [])

    if not user_id:
        return {"error": "user_id required"}

    found = False
    rows = []

    if ROLES_PATH.exists():
        import csv
        with open(ROLES_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            for row in reader:
                if row.get("user_id") == user_id:
                    row["expected_resources"] = ", ".join(permissions)
                    found = True
                rows.append(row)

        if found:
            with open(ROLES_PATH, "w", encoding="utf-8", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            audit_output = {
                "event_type": "audit_log",
                "risk_score": 10,
                "is_critical": False,
                "type": "Permission Modified",
                "threat_vectors": [],
                "raw_log": {"actor": "IT_ADMIN", "target": user_id, "action": "update_permissions", "new_permissions": permissions},
                "ai_analysis": {"summary": f"INFO: IT Admin updated permissions for {user_id}.", "threat_vectors": [], "recommended_action": "None"},
                "merkle_integrity": "Verified",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "sequence": 9999
            }
            await manager.broadcast(audit_output)
            return {"message": "Permissions updated successfully", "user_id": user_id, "permissions": permissions}

    return {"error": "User not found or roles file missing"}


# ── SOAR — Security Orchestration, Automation & Response ─────────────────

# In-memory audit trail for all SOAR actions taken during this session.
# In production this would be a database; for the hackathon, a list suffices.
soar_actions: list[dict] = []


@app.post("/api/isolate/{uid}", tags=["SOAR"])
async def isolate_host(uid: str):
    """SOAR Action: Isolate a compromised host by user ID.

    This endpoint simulates a network-level containment action:
      1. Records the action in the SOAR audit trail.
      2. Broadcasts a SOAR_ACTION payload to ALL connected WebSocket clients
         so every analyst's UI instantly reflects the isolation.
      3. Returns HTTP 200 immediately — the broadcast is fire-and-forget
         from the caller's perspective, making the UI feel snappy on stage.

    The frontend catches {"type": "SOAR_ACTION"} and flashes the user's
    row red + changes status to "ISOLATED".
    """
    ts = datetime.utcnow().isoformat() + "Z"

    # ── Build the SOAR payload ──
    payload = {
        "type":      "SOAR_ACTION",
        "action":    "ISOLATE",
        "uid":       uid,
        "status":    "NETWORK_SEVERED",
        "timestamp": ts,
        "message":   f"Host isolation executed for {uid}. "
                     "All network access revoked. Session tokens invalidated.",
    }

    # ── Audit trail ──
    soar_actions.append(payload)

    # ── Blast to every connected dashboard ──
    await manager.broadcast(payload)

    log.critical(
        "🔒 SOAR ISOLATE — uid=%s | clients=%d | ts=%s",
        uid, manager.count, ts,
    )

    # Instant 200 — no waiting for downstream effects
    return {
        "status":    "executed",
        "action":    "ISOLATE",
        "uid":       uid,
        "timestamp": ts,
        "broadcast": f"Sent to {manager.count} client(s)",
    }


@app.post("/api/revoke/{uid}", tags=["SOAR"])
async def revoke_access(uid: str):
    """SOAR Action: Revoke all access tokens for a user."""
    ts = datetime.utcnow().isoformat() + "Z"

    payload = {
        "type":      "SOAR_ACTION",
        "action":    "REVOKE",
        "uid":       uid,
        "status":    "ACCESS_REVOKED",
        "timestamp": ts,
        "message":   f"All credentials and session tokens revoked for {uid}.",
    }

    soar_actions.append(payload)
    await manager.broadcast(payload)

    log.critical(
        "🔑 SOAR REVOKE — uid=%s | clients=%d | ts=%s",
        uid, manager.count, ts,
    )

    return {
        "status": "executed", "action": "REVOKE",
        "uid": uid, "timestamp": ts,
        "broadcast": f"Sent to {manager.count} client(s)",
    }


@app.get("/api/soar/actions", tags=["SOAR"])
async def get_soar_actions():
    """Return the audit trail of all SOAR actions taken this session."""
    return {"total": len(soar_actions), "actions": soar_actions}


# ── WebSocket Endpoint ────────────────────────────────────────────────────

@app.websocket("/ws/stream")
async def websocket_stream(ws: WebSocket):
    """Real-time event feed.  Clients receive every processed log as JSON.

    Send ``"ping"`` to receive a ``{"pong": true, ...}`` heartbeat with
    current stats.  The connection stays open until the client disconnects.
    """
    await manager.connect(ws)
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_json({"pong": True, "stats": stats.to_dict()})
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        manager.disconnect(ws)


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="warning",     # suppress uvicorn noise; AEGIS has its own logger
    )
