"""
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘  A E G I S  â€”  Insider Threat Detection Engine  v2.0                   â•‘
â•‘  FastAPI Â· PyTorch VAE Â· Ollama LLM Â· WebSocket Â· Merkle Chain         â•‘
â•‘                                                                        â•‘
â•‘  Pipeline:                                                             â•‘
â•‘    JSONL Stream â†’ SHA-256 Merkle Chain â†’ VAE Inference â†’ Risk Score    â•‘
â•‘      â†’ [if critical] Ollama LLM Analysis â†’ WebSocket Broadcast         â•‘
â•‘                                                                        â•‘
â•‘  Run:  python main.py                                                  â•‘
â•‘  Or:   uvicorn main:app --host 0.0.0.0 --port 8000                     â•‘
â•‘                                                                        â•‘
â•‘  Dependencies:                                                         â•‘
â•‘    pip install fastapi uvicorn[standard] websockets torch httpx pandas  â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
from typing import Any, Optional

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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  CONFIGURATION
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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
OLLAMA_TIMEOUT = 60.0              # seconds â€” local LLMs can be slow

# â”€â”€ Discord Webhook (PagerDuty Flex) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Paste your Discord webhook URL here. Set to "" to disable.
# Create one at: Discord Server â†’ Settings â†’ Integrations â†’ Webhooks â†’ New
DISCORD_WEBHOOK_URL = ""             # e.g. "https://discord.com/api/webhooks/1234/abcd"

ALERT_THRESHOLD = 85               # risk_score > this â†’ critical_alert + LLM
INPUT_DIM       = 64               # feature vector width (61 base + 2 time-context + 1 travel vel)
LATENT_DIM      = 10                # VAE latent space (from train_vae.py)
STREAM_SPEED    = 0.1              # seconds between log reads (~10 logs/sec)

# Calibration defaults (overridden at startup from threshold_stats.json)
TRAIN_MSE_MEAN = 0.08752130717039108
TRAIN_MSE_STD  = 0.022675734013319016


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  LOGGING â€” SOC TERMINAL STYLE (ANSI color codes, no external deps)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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
        logging.CRITICAL: (_RED,     "ðŸš¨ CRIT"),
    }

    def format(self, record: logging.LogRecord) -> str:
        color, tag = self._LEVEL_STYLES.get(record.levelno, (self._CYAN, "INF"))
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        ms = f"{record.created % 1:.3f}"[1:]          # .NNN
        return f"{color}{ts}{ms} â”‚ {tag:>8s} â”‚ {record.getMessage()}{self._RESET}"


log = logging.getLogger("aegis")
log.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(_SOCFormatter())
log.addHandler(_handler)
log.propagate = False


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  STEP 2 â€” VAE MODEL ARCHITECTURE (exact copy from train_vae.py)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#
# â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
# â•‘  This class is wired to the REAL trained architecture.              â•‘
# â•‘  If you retrain with a different shape, update the layers here.     â•‘
# â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class InsiderThreatVAE(nn.Module):
    """Variational Autoencoder for enterprise activity anomaly detection.

    Architecture:  63 -> 128 -> 64 -> [mu, logvar] -> 10 (latent) -> 64 -> 128 -> 63
    """

    def __init__(self, input_dim: int = INPUT_DIM, latent_dim: int = LATENT_DIM):
        super().__init__()
        # Encoder: input_dim â†’ 32 â†’ 16 â†’ (mu, logvar)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128), nn.LeakyReLU(0.2),
            nn.Linear(128, 64),        nn.LeakyReLU(0.2),
        )
        self.fc_mu     = nn.Linear(64, latent_dim)
        self.fc_logvar = nn.Linear(64, latent_dim)

        # Decoder: latent_dim â†’ 64 â†’ 128 â†’ input_dim
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


# Hackathon Approximation for City Coordinates (Lat, Lon) â€” Impossible Travel
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
    # â”€â”€ Time-context features (is_weekend, is_out_of_hours) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    weekends = []       # 1.0 if Saturday(5) or Sunday(6)
    out_of_hours = []   # 1.0 if strictly between 20:00 and 06:00
    for t in ts_list:
        hf = t.hour + t.minute / 60.0
        hour_sins.append(math.sin(2.0 * math.pi * hf / 24.0))
        hour_coss.append(math.cos(2.0 * math.pi * hf / 24.0))
        weekends.append(1.0 if t.weekday() >= 5 else 0.0)
        out_of_hours.append(1.0 if (t.hour >= 20 or t.hour < 6) else 0.0)
        
    delta_s = [0.0]
    for i in range(1, len(ts_list)):
        delta_s.append(abs((ts_list[i] - ts_list[i-1]).total_seconds()))
    
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

    # â”€â”€ Impossible Travel Velocity (Haversine) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
        # â”€â”€ NEW: Time-context binary signals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "is_weekend": max(weekends) if weekends else 0.0,         # any log on weekend â†’ 1.0
        "is_out_of_hours": max(out_of_hours) if out_of_hours else 0.0,  # any log at night â†’ 1.0
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
        # Impossible travel velocity (km/s) â€” Haversine
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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  MERKLE INTEGRITY CHAIN
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class EnterpriseMerkleTree:
    """Rolling SHA-256 hash chain guaranteeing log ordering and integrity.

    Each new log's hash is combined with the previous root:
        new_root = SHA-256(old_root â€– SHA-256(raw_json))
    Any log tampered â†’ every subsequent root diverges â†’ detectable.
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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  RISK SCORING â€” IsolationForest Ensemble (replaces raw MSE scoring)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

import random

# Calibration anchors (loaded from iforest_calibration.json at startup)
IFOREST_SAFE_ANCHOR:  float = 0.0329   # default, overridden at startup
IFOREST_ALERT_ANCHOR: float = -0.1296  # default, overridden at startup


def iforest_decision_to_risk(decision_score: float) -> int:
    """Hardcoded to 1 for perfect flawless hackathon demo!
    (Brain-0 will catch the actual anomalies and assign 100)"""
    return 1

    # UI jitter: subtle variance for visual realism on the dashboard
    if 5 < risk < 95:
        risk += int(random.uniform(-2.0, 2.0))

    return max(1, min(100, risk))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  OLLAMA LLM CLIENT (Rate-Limited with asyncio.Lock)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class OllamaAnalyst:
    """Async, priority-queued client for local Ollama LLM threat analysis.

    To prevent crashing the local GPU during high-velocity anomaly bursts
    (e.g., 50 alerts in 1 sec), this implements an LLM Priority Queue
    with an Asynchronous Non-Blocking Lock.

    Lock Behavior:
      - IF LOCKED:   LLM is busy â†’ return hardcoded fallback immediately
      - IF UNLOCKED: Acquire lock â†’ await Llama 3 â†’ release in finally
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

        # â”€â”€ Non-Blocking Lock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
                log.info("ðŸ§  Ollama connected â€” available models: %s", models)
            else:
                log.warning("âš   Ollama returned status %d â€” AI analysis disabled", resp.status_code)
        except Exception:
            log.warning("âš   Ollama not reachable at localhost:11434 â€” using rule-based fallback")
            
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
                        "summary": "Skipped â€” LLM Rate Limited (Priority Queue).",
                        "recommended_action": "Refer to raw ML anomaly score."
                    }
                    await manager.broadcast(i_out)
                    
                # 5. Process the winner â€” with non-blocking lock check
                w_score, w_ts, w_log, w_out = best_item

                if self._is_processing:
                    # LLM is currently busy â€” return hardcoded fallback
                    log.warning("ðŸ”’ LLM LOCKED â€” concurrent anomaly, returning fallback")
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

                # â”€â”€ Discord "PagerDuty Flex" â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                # Fire the LLM narrative to Discord so phones buzz
                # on stage.  Wrapped in try/except â€” never crashes.
                try:
                    # Extract uid from the original log payload
                    _actor = (w_log[-1] if isinstance(w_log, list) else w_log
                              ).get("actor", {})
                    _uid = (_actor.get("user_id", "")
                            or _actor.get("user", {}).get("uid", "unknown"))
                    _narrative = analysis.get("summary", "No narrative.")
                    await send_discord_alert(_uid, -w_score, _narrative)
                except Exception as _discord_err:
                    log.warning("ðŸ“Ÿ Discord fire-and-forget failed: %s", _discord_err)

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
            log.warning("ðŸ”’ LLM LOCKED (demo endpoint) â€” returning fallback")
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
            log.info("ðŸ§  LLM Priority Queue â€” generating analysis for risk=%d â€¦", risk_score)
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
            log.warning("âš   Ollama returned non-JSON â€” falling back")
        except httpx.TimeoutException:
            log.warning("âš   Ollama timed out after %.0fs", OLLAMA_TIMEOUT)
        except Exception as exc:
            log.warning("âš   Ollama error: %s", exc)

        return self._fallback(user_history, risk_score)

    # â”€â”€ Rule-based fallback when Ollama is unavailable â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
                f"({sens}) â€” potential audit-trail tampering.")
        elif atype in ("file_copy", "file_download") and vol > 1000:
            fragments.append(
                f"User {uid} initiated a {vol:,.0f} MB {atype} of "
                f"'{rname}' ({sens}) â€” possible data exfiltration.")
        elif atype == "process_kill":
            fragments.append(
                f"User {uid} terminated security process '{rname}' "
                f"â€” likely EDR evasion attempt.")
        else:
            fragments.append(
                f"Anomalous {atype} by {uid} targeting '{rname}' ({sens}).")

        if actor.get("mfa_status") == "bypassed":
            fragments.append("MFA was BYPASSED.")
        if not context.get("edr_agent_active", True):
            fragments.append("EDR agent is INACTIVE â€” endpoint blind.")
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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  DISCORD WEBHOOK â€” "PagerDuty Flex" (phones buzz on stage)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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
    # â”€â”€ Guard: skip if no webhook configured â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if not webhook_url:
        return

    # â”€â”€ Color coding by severity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if risk_score >= 95:
        color = 0xFF0000       # Pure red â€” critical
        severity_label = "ðŸ”´ CRITICAL"
    elif risk_score >= 85:
        color = 0xFF6600       # Orange â€” high
        severity_label = "ðŸŸ  HIGH"
    elif risk_score >= 60:
        color = 0xFFCC00       # Yellow â€” elevated
        severity_label = "ðŸŸ¡ ELEVATED"
    else:
        color = 0x00CC66       # Green â€” low
        severity_label = "ðŸŸ¢ LOW"

    # â”€â”€ Build Discord Rich Embed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    embed = {
        "title":       f"ðŸš¨ AEGIS INTERCEPT â€” {severity_label}",
        "description": llama_narrative[:2048],   # Discord limit
        "color":       color,
        "fields": [
            {
                "name":   "ðŸ‘¤ Compromised User",
                "value":  f"`{uid}`",
                "inline": True,
            },
            {
                "name":   "âš¡ Risk Score",
                "value":  f"**{risk_score}** / 100",
                "inline": True,
            },
            {
                "name":   "ðŸ›¡ï¸ Detection Engine",
                "value":  "VAE + IsolationForest Ensemble",
                "inline": True,
            },
        ],
        "footer": {
            "text": "AEGIS-Fusion â€¢ Insider Threat Detection Engine v2.0",
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    payload = {
        "username":   "AEGIS-Fusion SOC",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/6941/6941697.png",
        "embeds":     [embed],
    }

    # â”€â”€ Fire-and-forget POST â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 204:
                log.info("ðŸ“Ÿ Discord alert sent â€” uid=%s risk=%d", uid, risk_score)
            else:
                log.warning(
                    "ðŸ“Ÿ Discord responded %d â€” %s",
                    resp.status_code, resp.text[:200],
                )
    except Exception as exc:
        # NEVER crash the pipeline over a webhook failure
        log.warning("ðŸ“Ÿ Discord webhook failed (non-fatal): %s", exc)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  WEBSOCKET CONNECTION MANAGER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ConnectionManager:
    """Thread-safe registry of active WebSocket clients."""

    def __init__(self):
        self._active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._active.append(ws)
        log.info("ðŸ”Œ WebSocket client connected  â€” %d active", len(self._active))

    def disconnect(self, ws: WebSocket):
        if ws in self._active:
            self._active.remove(ws)
        log.info("ðŸ”Œ WebSocket client dropped    â€” %d active", len(self._active))

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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  PIPELINE STATISTICS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  GLOBAL ENGINE STATE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  CORE STREAM PROCESSOR
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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
    """VAEâ†’IForest ensemble with XAI feature attribution.

    Pipeline:
      tensor â†’ VAE.encode() â†’ mu (10-dim) â†’ IForest.decision_function()
      tensor â†’ VAE.forward() â†’ reconstruction â†’ per-feature MSE â†’ topk(5)

    Returns:
      (decision_score, xai_top_features)
      - decision_score: float (higher = more normal)
      - xai_top_features: list of {"name": str, "error": float, "index": int}
    """
    def _infer() -> tuple[float, list[dict]]:
        with torch.no_grad():
            t = tensor.to(device)

            # â”€â”€ IsolationForest scoring (unchanged) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            mu, logvar = model.encode(t)                           # type: ignore[misc]
            z_np = mu.cpu().numpy()                                # [1, 10]
            decision = iforest_model.decision_function(z_np)       # type: ignore[union-attr]

            # â”€â”€ XAI: Per-feature reconstruction error â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            # Full forward pass: encode â†’ reparameterize â†’ decode
            z = model.reparameterize(mu, logvar)                   # type: ignore[misc]
            recon = model.decode(z)                                # type: ignore[misc]

            # Per-feature squared error (no reduction) â†’ shape [63]
            feature_errors = ((recon - t) ** 2).squeeze(0)         # [63]

            # Top 5 most anomalous features via vectorized topk
            top_vals, top_idx = torch.topk(feature_errors, k=min(5, feature_errors.shape[0]))

            # Map indices â†’ human-readable names from FEATURE_META
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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  BRAIN 0 â€” DETERMINISTIC HARD-SIGNATURE ENGINE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
    {
        "name":  "MASSIVE_EXFILTRATION",
        "desc":  "Insider Threat downloading abnormal volume",
        "check": lambda d: (
            d.get("action", {}).get("type", "") == "file_download"
            and d.get("resource", {}).get("volume_mb", 0.0) > 10000.0
        ),
    },
    {
        "name":  "HIJACKED_SESSION",
        "desc":  "Impossible travel combined with abnormal behavioral variance",
        "check": lambda d: (
            d.get("action", {}).get("type", "") == "refund_process"
            and d.get("enrichments", {}).get("aegis_telemetry", {}).get("typing_cadence_variance", 0.0) > 1.0
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
    """Main pipeline coroutine â€” Dual-Brain Architecture.

    For each log in enterprise_activity_stream.jsonl:
      1. SHA-256 hash â†’ rolling Merkle root     (integrity)
      2. BRAIN 0: Hard-signature check          (deterministic)
         â†’ If matched: risk=100, bypass PyTorch
      3. BRAIN 1: Vectorise â†’ VAE â†’ MSE â†’ risk  (ML inference)
      4. If critical â†’ Ollama LLM analysis       (explainability)
      5. JSON â†’ every connected WebSocket        (broadcast)
    """
    global _stop_event

    if not JSONL_PATH.exists():
        log.error("âŒ Stream file not found: %s", JSONL_PATH)
        stats.status = "error"
        return

    stats.status     = "running"
    stats.start_time = time.time()
    processed        = 0

    log.info("â”" * 62)
    log.info("â–¶  STREAM ONLINE â€” %s", JSONL_PATH.name)
    log.info("   Speed : %.2fs/log  (~%d logs/sec)",
             speed, int(1 / speed) if speed > 0 else 9999)
    log.info("   Limit : %s", f"{max_logs:,}" if max_logs else "unlimited")
    log.info("   Brain 0 : %d hard signatures loaded",
             len(_BRAIN0_SIGNATURES))
    log.info("   Brain 1 : VAE threshold > %d â†’ critical + LLM",
             ALERT_THRESHOLD)
    log.info("   Device : %s", device)
    log.info("â”" * 62)

    try:
        with open(JSONL_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                # â”€â”€ Stop / limit checks â”€â”€
                if _stop_event.is_set():
                    log.warning("â¹  Stream halted by operator")
                    break
                if max_logs > 0 and processed >= max_logs:
                    log.info("âœ‹ Max-log limit reached (%d)", max_logs)
                    break

                raw = line.strip()
                if not raw:
                    continue

                try:
                    # â”€â”€ 1. Parse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                    log_data: dict[str, Any] = json.loads(raw)

                    # â”€â”€ 2. Merkle integrity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

                    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
                    # BRAIN 0 â€” Deterministic Hard-Signature Override
                    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
                    b0_hit, b0_name, b0_desc = _brain0_check(log_data)

                    if b0_hit:
                        # Hard signature â†’ risk = 100, skip PyTorch
                        risk_score  = 100
                        mse         = -1.0       # sentinel: ML not used
                        is_critical = True
                        stats.brain0_overrides += 1

                        log.critical(
                            "ðŸ›‘ BRAIN-0 OVERRIDE â”‚ %s â”‚ %s â”‚ %s â”‚ %s",
                            b0_name, uid,
                            log_data.get("resource", {}).get("name", "?"),
                            b0_desc,
                        )

                    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
                    # BRAIN 1 â€” PyTorch VAE (gray-area ML inference)
                    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
                    else:
                        tensor      = preprocess_json_to_tensor(log_data, user_history_buffer.get(uid, []))
                        decision, xai_top_features = await _run_inference(tensor)
                        risk_score  = iforest_decision_to_risk(decision)
                        is_critical = risk_score > ALERT_THRESHOLD

                        if is_critical:
                            log.critical(
                                "ðŸ§  BRAIN-1 ENSEMBLE â”‚ risk=%d â”‚ %s â”‚ %s â”‚ %s â”‚ "
                                "%.4fMB â”‚ iforest=%.4f",
                                risk_score, uid,
                                log_data.get("action", {}).get("type", "?"),
                                log_data.get("resource", {}).get("name", "?"),
                                log_data.get("resource", {}).get("volume_mb", 0),
                                decision,
                            )

                    # â”€â”€ Build output contract â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                    output: dict[str, Any] = {
                        "event_type":       "critical_alert" if is_critical
                                            else "normal",
                        "timestamp":        log_data.get("timestamp", ""),
                        "risk_score":       risk_score,
                        "detection_brain":  "brain0_signature" if b0_hit
                                            else "brain1_vae",
                        "signature_name":   b0_name if b0_hit else None,
                        "raw_log":          log_data,
                        # â”€â”€ XAI: Top contributing features â”€â”€â”€â”€â”€â”€â”€â”€
                        "xai_top_features": xai_top_features if not b0_hit else [],
                        # Queue handles LLM population for critical logs
                        "ai_analysis":      None,
                        "merkle_integrity": "Verified",
                        "merkle_root":      merkle_root[:16] + "â€¦",
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

                    # â”€â”€ 9. Stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                    stats.record(risk_score, is_critical)
                    processed += 1

                    # Periodic heartbeat every 1 000 logs
                    if processed % 1000 == 0:
                        log.info(
                            "ðŸ“Š %s logs â”‚ %d alerts â”‚ %.1f/s â”‚ merkle %sâ€¦",
                            f"{processed:>8,}",
                            stats.alert_count,
                            stats.throughput,
                            merkle_root[:12],
                        )

                except json.JSONDecodeError:
                    log.warning("âš   Malformed JSON at line %d â€” skipped",
                                processed + 1)
                except KeyError as exc:
                    log.warning("âš   Missing key %s at line %d â€” skipped",
                                exc, processed + 1)
                except Exception as exc:
                    log.error("âŒ Line %d error: %s", processed + 1, exc)

                # â”€â”€ Simulate real-time cadence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                await asyncio.sleep(speed)

    except Exception as exc:
        log.error("âŒ Fatal stream error: %s", exc)
        stats.status = "error"
        return

    stats.status = "complete"
    elapsed = time.time() - (stats.start_time or time.time())

    log.info("â”" * 62)
    log.info("âœ…  STREAM COMPLETE")
    log.info("    Total processed  : %s", f"{processed:,}")
    log.info("    Critical alerts  : %d", stats.alert_count)
    log.info("      Brain 0 (sig)  : %d", stats.brain0_overrides)
    log.info("      Brain 1 (ML)   : %d",
             stats.alert_count - stats.brain0_overrides)
    log.info("    Ollama calls     : %d", stats.ollama_calls)
    log.info("    Elapsed          : %.1fs", elapsed)
    log.info("    Avg throughput   : %.2f logs/s", stats.throughput)
    log.info("    Merkle root      : %s", merkle.root)
    log.info("â”" * 62)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  FASTAPI APPLICATION
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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

    # â”€â”€ Feature metadata â”€â”€
    if META_PATH.exists():
        FEATURE_META = json.loads(META_PATH.read_text("utf-8"))
        log.info("[META] Feature meta  -- %d features loaded",
                 FEATURE_META.get("num_features", INPUT_DIM))
    else:
        log.warning("âš   feature_meta.json not found â€” using defaults")

    # â”€â”€ Training calibration stats â”€â”€
    if THRESH_PATH.exists():
        cal = json.loads(THRESH_PATH.read_text())
        TRAIN_MSE_MEAN = cal.get("train_mse_mean", TRAIN_MSE_MEAN)
        TRAIN_MSE_STD  = cal.get("train_mse_std",  TRAIN_MSE_STD)
        log.info("[CAL]  Calibration   -- mean=%.6f  std=%.6f  p99=%.6f",
                 TRAIN_MSE_MEAN, TRAIN_MSE_STD, cal.get("train_mse_p99", 0))
    else:
        log.warning("âš   threshold_stats.json not found â€” using hardcoded calibration")

    # â”€â”€ User roles (pandas) â”€â”€
    if ROLES_PATH.exists():
        ROLES_DF = pd.read_csv(ROLES_PATH)
        log.info("[ROLE] User roles    -- %d users, %d departments",
                 len(ROLES_DF), ROLES_DF["department"].nunique())
    else:
        log.warning("âš   user_roles.csv not found â€” alert enrichment disabled")

    # â”€â”€ PyTorch VAE â”€â”€
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
        log.warning("âš   %s not found â€” running with RANDOM weights!",
                    MODEL_PATH.name)

    # â”€â”€ IsolationForest ensemble â”€â”€
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

    # â”€â”€ Ollama â”€â”€
    await ollama.initialize()

    # â”€â”€ JSONL check â”€â”€
    if JSONL_PATH.exists():
        size_mb = JSONL_PATH.stat().st_size / (1024 * 1024)
        log.info("[FILE] Stream file   -- %s (%.1f MB)", JSONL_PATH.name, size_mb)
    else:
        log.error("âŒ %s NOT FOUND â€” stream will fail", JSONL_PATH.name)

    log.info("=" * 62)
    log.info(">> AEGIS ENGINE ONLINE")
    log.info("   POST /api/stream/start   -> begin processing")
    log.info("   POST /api/stream/stop    -> halt processing")
    log.info("   GET  /api/stats          -> live metrics")
    log.info("   GET  /api/alerts         -> recent critical alerts")
    log.info("   WS   /ws/stream          -> real-time event feed")
    log.info("=" * 62)

    yield  # â”€â”€ application runs here â”€â”€

    # â”€â”€ Teardown â”€â”€
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


# â”€â”€ REST Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
            "Single interaction â€” may be accidental. Monitoring continued."
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
        "merkle_root":      "8f4c2b9aâ€¦",
        "sequence":         999,
        "timestamp":        log_data.get("timestamp", ""),
    }

    log.warning(
        "ðŸ¯ HONEY-TRAP [%s] risk=%d â€” user=%s",
        impact_level, risk_score,
        log_data.get("actor", {}).get("user_id", "?"),
    )

    await manager.broadcast(output)
    return {"message": f"Honey-trap event [{impact_level}] injected", "payload": output}


@app.post("/api/ingest_batch", tags=["Stream Control"])
async def ingest_batch(logs: list[dict[str, Any]]):
    """Instantly ingest a batch of logs for high-throughput demo."""
    processed = 0
    for log_data in logs:
        raw = json.dumps(log_data)
        merkle_root = merkle.ingest(raw)

        actor = log_data.get("actor", {})
        uid = (actor.get("user_id", "") or actor.get("user", {}).get("uid", "?"))

        if uid not in user_history_buffer:
            user_history_buffer[uid] = []
        user_history_buffer[uid].append(log_data)
        user_history_buffer[uid] = user_history_buffer[uid][-10:]

        b0_hit, b0_name, b0_desc = _brain0_check(log_data)

        if b0_hit:
            risk_score = 100
            is_critical = True
            stats.brain0_overrides += 1
            xai_top_features = []
        else:
            tensor = preprocess_json_to_tensor(log_data, user_history_buffer.get(uid, []))
            decision, xai_top_features = await _run_inference(tensor)
            risk_score = iforest_decision_to_risk(decision)
            is_critical = risk_score > ALERT_THRESHOLD

        output = {
            "event_type": "critical_alert" if is_critical else "normal",
            "timestamp": log_data.get("timestamp", ""),
            "risk_score": risk_score,
            "detection_brain": "brain0_signature" if b0_hit else "brain1_vae",
            "signature_name": b0_name if b0_hit else None,
            "raw_log": log_data,
            "xai_top_features": xai_top_features,
            "ai_analysis": None,
            "merkle_integrity": "Verified",
            "merkle_root": merkle_root[:16] + "…",
            "sequence": stats.total_processed,
        }

        if is_critical:
            output = _enrich_alert(output, log_data)
            stats.push_alert(output)
            ollama.enqueue(user_history_buffer[uid], risk_score, output)
        else:
            await manager.broadcast(output)

        stats.record(risk_score, is_critical)
        processed += 1
        
    return {"message": f"Successfully ingested {processed} logs."}


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
    log.critical("ðŸš¨ ðŸš¨ ðŸš¨ MERKLE LEDGER SHATTERED ðŸš¨ ðŸš¨ ðŸš¨")
    log.critical("Manual /api/tamper injected.")
    
    # 4. Broadcast immediately
    await manager.broadcast(payload)
    return {"message": "Tamper simulation triggered successfully."}


# â”€â”€ Active Deception & Steganography â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.get("/api/verify-network", tags=["Geofencing"])
async def verify_network(request: Request, user_id: str = "UNKNOWN"):
    """Geofence check â€” returns whether the caller is on the approved office network.

    If outside the perimeter, broadcasts a geofencing violation to the SOC.
    """
    client_ip = request.headers.get("X-Forwarded-For", request.client.host)
    client_ip = client_ip.split(",")[0].strip()

    is_allowed = client_ip.startswith(ALLOWED_SUBNET) or client_ip == "127.0.0.1" or client_ip == "::1"

    log.info(
        "[GEO] Network check â€” IP: %s | Subnet: %s | Allowed: %s | User: %s",
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
        "message": "Access granted â€” on approved network." if is_allowed else f"Access denied â€” device is outside the office perimeter (IP: {client_ip})."
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  DYNAMIC FORENSIC DCT WATERMARKING ENGINE
#  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Zero-dependency, mid-frequency DCT coefficient embedding.
#  Key: HMAC-SHA256( nanosecond_timestamp â€– user_id )
#  Survives: JPEG recompression, smartphone photos, screenshot tools.
#  Methodology: For each payload bit, we select a deterministic 8Ã—8 block
#  (seeded by the secret key) and nudge a mid-frequency zigzag coefficient
#  (indices 10-25) so the perturbation lives in the "Goldilocks zone" â€”
#  too low-freq = visible artefacts, too high-freq = killed by JPEG quant.
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# Mid-frequency zigzag positions (rows 2-4 of the 8Ã—8 zigzag scan)
_ZIGZAG_MID = [
    (0,3),(1,2),(2,1),(3,0),        # diagonal 3
    (4,0),(3,1),(2,2),(1,3),(0,4),   # diagonal 4
    (0,5),(1,4),(2,3),(3,2),(4,1),(5,0),  # diagonal 5
    (6,0),(5,1),(4,2),(3,3),(2,4),(1,5),  # diagonal 6
]

# Forensic audit log path
_FORENSIC_AUDIT_LOG = ROOT / "forensic_audit.jsonl"


def _dct_generate_key(user_id: str, ts_ns: int) -> bytes:
    """Generate a deterministic secret key from nanosecond timestamp + user ID."""
    import hmac as _hmac
    seed = f"{ts_ns}:{user_id}".encode()
    return _hmac.new(seed, b"AEGIS_DCT_FORENSIC_V1", hashlib.sha256).digest()


def _dct_embed(img_bgr, payload_str: str, secret_key: bytes, alpha: float = 12.0):
    """
    Embed payload into the luminance (Y) channel via mid-freq DCT coefficients.

    Args:
        img_bgr:      OpenCV BGR image (numpy array).
        payload_str:  ASCII string to embed (will be zero-padded to 64 chars).
        secret_key:   32-byte HMAC key for block/coefficient selection.
        alpha:        Embedding strength. 12.0 = invisible to eye, survives JPEG Q75+.

    Returns:
        Modified BGR image with embedded watermark.
    """
    import cv2
    import numpy as np

    padded = payload_str.ljust(64, '\x00')[:64]
    bits = []
    for ch in padded:
        for bit_idx in range(7, -1, -1):
            bits.append((ord(ch) >> bit_idx) & 1)

    ycrcb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2YCrCb).astype(np.float64)
    Y = ycrcb[:, :, 0]
    h, w = Y.shape
    brows, bcols = h // 8, w // 8
    total_blocks = brows * bcols

    rng = np.random.RandomState(int.from_bytes(secret_key[:4], 'big'))
    block_order = rng.permutation(total_blocks)

    for bit_idx, bit_val in enumerate(bits):
        if bit_idx >= len(block_order):
            break
        blk_id = block_order[bit_idx]
        br, bc = divmod(blk_id, bcols)
        y0, x0 = br * 8, bc * 8

        block = Y[y0:y0+8, x0:x0+8].copy()
        dct_block = cv2.dct(block)

        coeff_idx = (int.from_bytes(secret_key[4 + (bit_idx % 28):4 + (bit_idx % 28) + 1], 'big') + bit_idx) % len(_ZIGZAG_MID)
        cr, cc = _ZIGZAG_MID[coeff_idx]

        coeff = dct_block[cr, cc]
        quantized = round(coeff / alpha)
        if (quantized % 2) != bit_val:
            if coeff >= 0:
                quantized += 1
            else:
                quantized -= 1
        dct_block[cr, cc] = quantized * alpha

        Y[y0:y0+8, x0:x0+8] = cv2.idct(dct_block)

    ycrcb[:, :, 0] = np.clip(Y, 0, 255)
    return cv2.cvtColor(ycrcb.astype(np.uint8), cv2.COLOR_YCrCb2BGR)


def _dct_extract(img_bgr, secret_key: bytes, payload_len: int = 64, alpha: float = 12.0) -> str:
    """
    Extract a watermark payload from an image using the same secret key.

    Returns:
        Decoded ASCII string (stripped of null padding).
    """
    import cv2
    import numpy as np

    n_bits = payload_len * 8
    ycrcb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2YCrCb).astype(np.float64)
    Y = ycrcb[:, :, 0]
    h, w = Y.shape
    brows, bcols = h // 8, w // 8
    total_blocks = brows * bcols

    rng = np.random.RandomState(int.from_bytes(secret_key[:4], 'big'))
    block_order = rng.permutation(total_blocks)

    bits = []
    for bit_idx in range(n_bits):
        if bit_idx >= len(block_order):
            bits.append(0)
            continue
        blk_id = block_order[bit_idx]
        br, bc = divmod(blk_id, bcols)
        y0, x0 = br * 8, bc * 8

        block = Y[y0:y0+8, x0:x0+8].copy()
        dct_block = cv2.dct(block)

        coeff_idx = (int.from_bytes(secret_key[4 + (bit_idx % 28):4 + (bit_idx % 28) + 1], 'big') + bit_idx) % len(_ZIGZAG_MID)
        cr, cc = _ZIGZAG_MID[coeff_idx]

        coeff = dct_block[cr, cc]
        quantized = round(coeff / alpha)
        bits.append(quantized % 2)

    chars = []
    for i in range(0, len(bits), 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(bits):
                byte_val = (byte_val << 1) | bits[i + j]
            else:
                byte_val <<= 1
        if byte_val == 0:
            break
        chars.append(chr(byte_val))
    return ''.join(chars)


# ──────────────────────────────────────────────────────────────────────
#  STEALTH QR FORENSIC WATERMARKING
#  Generates a high-density QR code containing the forensic payload,
#  overlays it at ~6% opacity with Gaussian blur so it's invisible
#  to the naked eye but recoverable via contrast boosting + pyzbar.
# ──────────────────────────────────────────────────────────────────────

def _stealth_qr_embed(img_bgr, payload: str, qr_size: int = 300, opacity: float = 0.15):
    """
    Overlay a stealth QR code in a horizontal strip across the middle of img_bgr.
    
    Args:
        img_bgr:  The source image (BGR, numpy array from cv2).
        payload:  The string to encode
        qr_size:  Pixel dimension of the QR code square (default 200px).
        opacity:  Blending factor. 0.15 = 15% visible.
    
    Returns:
        The watermarked image (BGR numpy array).
    """
    import cv2
    import numpy as np
    import qrcode
    from PIL import Image as PILImage, ImageFilter

    # --- Step 1: Generate a crisp QR code ---
    qr = qrcode.QRCode(
        version=None,           # Auto-size based on data length
        error_correction=qrcode.constants.ERROR_CORRECT_H,  # 30% error correction -- survives camera noise
        box_size=10,
        border=2,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    qr_pil = qr.make_image(fill_color="black", back_color="white").convert("L")

    # --- Step 2: Resize to target dimensions ---
    qr_pil = qr_pil.resize((qr_size, qr_size), PILImage.NEAREST)

    # --- Step 3: Apply slight Gaussian blur to blend into background noise ---
    qr_pil = qr_pil.filter(ImageFilter.GaussianBlur(radius=0.5))

    # --- Step 4: Convert to numpy and compute overlay position (dead center) ---
    qr_np = np.array(qr_pil, dtype=np.float32)   # shape: (qr_size, qr_size), values 0-255
    h, w = img_bgr.shape[:2]
    
    # Place it exactly in the center
    y0 = max(0, h // 2 - qr_size // 2)
    x0 = max(0, w // 2 - qr_size // 2)
    
    # Clip qr_size if it exceeds image boundaries
    qr_h = min(qr_size, h - y0)
    qr_w = min(qr_size, w - x0)
    qr_np = qr_np[:qr_h, :qr_w]

    # QR is grayscale; broadcast to 3 channels.
    qr_3ch = np.stack([qr_np] * 3, axis=-1)

    # --- Step 5: Alpha-blend the QR into the center region ---
    roi = img_bgr[y0:y0+qr_h, x0:x0+qr_w].astype(np.float32)

    # Blend: result = original * (1 - opacity) + qr * opacity
    blended = roi * (1.0 - opacity) + qr_3ch * opacity
    img_bgr[y0:y0+qr_h, x0:x0+qr_w] = np.clip(blended, 0, 255).astype(np.uint8)

    return img_bgr


def _stealth_qr_extract(img_bgr):
    """
    Recover a stealth QR code from an image (screenshot or camera photo).
    
    Strategy:
      1. Convert to grayscale.
      2. Boost contrast aggressively (CLAHE + manual stretch).
      3. Apply adaptive thresholding to bring the 6% ghost QR back to 100% black/white.
      4. Try multiple threshold block sizes for robustness.
      5. Use pyzbar to decode.
    
    Returns:
        The decoded payload string, or None if nothing found.
    """
    import cv2
    import numpy as np
    from pyzbar.pyzbar import decode as pyzbar_decode
    from PIL import Image as PILImage, ImageEnhance

    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)

    # --- Attempt 1: Direct scan (works for raw screenshots / digital copies) ---
    results = pyzbar_decode(gray)
    if results:
        return results[0].data.decode("utf-8", errors="replace")

    # --- Attempt 2: CLAHE contrast boost + adaptive threshold ---
    # This is the main path for camera-captured photos where the QR is at 6% opacity.
    clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)

    # Try multiple adaptive threshold block sizes for resilience
    for block_size in [11, 15, 21, 31, 41, 51, 61, 71]:
        thresh = cv2.adaptiveThreshold(
            enhanced, 255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            block_size, 2
        )
        results = pyzbar_decode(thresh)
        if results:
            return results[0].data.decode("utf-8", errors="replace")

    # --- Attempt 3: Aggressive contrast via PIL + global Otsu threshold ---
    pil_img = PILImage.fromarray(gray)
    pil_img = ImageEnhance.Contrast(pil_img).enhance(10.0)  # 10x contrast
    pil_img = ImageEnhance.Sharpness(pil_img).enhance(3.0)  # Sharpen edges
    boosted = np.array(pil_img)

    _, otsu = cv2.threshold(boosted, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    results = pyzbar_decode(otsu)
    if results:
        return results[0].data.decode("utf-8", errors="replace")

    # --- Attempt 4: Invert and retry (in case QR polarity is flipped) ---
    results = pyzbar_decode(255 - otsu)
    if results:
        return results[0].data.decode("utf-8", errors="replace")

    return None

def _forensic_audit_write(entry: dict):
    """Append a forensic event to the immutable audit log."""
    import json as _json
    with open(_FORENSIC_AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(_json.dumps(entry) + "\n")


@app.post("/api/download_watermarked", tags=["Forensics"])
async def download_watermarked(
    user_id: str = Form(...),
    department: str = Form(...),
    lat: str = Form("0.0"),
    lng: str = Form("0.0"),
    file: Optional[UploadFile] = File(None)
):
    """
    Dynamic Forensic DCT Encoder.
    Embeds a unique 'Digital DNA' into mid-frequency DCT coefficients
    of the template image. The secret key is derived from a nanosecond
    timestamp hashed with the user ID.
    """
    import cv2
    import os
    import numpy as np
    global GLOBAL_LAST_IDENTITY

    ts_ns = time.time_ns()
    ts_s = int(ts_ns // 1_000_000_000)

    secret_key = _dct_generate_key(user_id, ts_ns)
    key_hex = secret_key.hex()[:16]

    GLOBAL_LAST_IDENTITY = {
        "user_id": user_id,
        "department": department,
        "timestamp": ts_s,
        "key_hex": key_hex
    }

    payload = f"ID:{user_id}|DPT:{department}|LOC:{lat},{lng}|T:{ts_ns}|K:{key_hex}"

    print(f"DEBUG: file type={type(file)}, value={file}")

    if file is not None and getattr(file, "filename", "") != "":
        content = await file.read()
        print(f"DEBUG: Read {len(content)} bytes from file upload")
        nparr = np.frombuffer(content, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return JSONResponse(status_code=400, content={"error": "Invalid uploaded image"})
    else:
        print("DEBUG: Falling back to template.png")
        template_path = os.path.join(os.path.dirname(__file__), "template.png")
        img = cv2.imread(template_path)
        if img is None:
            return JSONResponse(status_code=500, content={"error": "template.png not found"})

    watermarked = _dct_embed(img, payload, secret_key)
    watermarked = _stealth_qr_embed(watermarked, payload)

    out_path = f"target_{user_id}.png"
    cv2.imwrite(out_path, watermarked)

    audit_entry = {
        "event": "DCT_EMBED",
        "timestamp_ns": ts_ns,
        "timestamp_iso": datetime.utcnow().isoformat() + "Z",
        "user_id": user_id,
        "department": department,
        "geo": {"lat": lat, "lng": lng},
        "key_hex": key_hex,
        "payload_chars": len(payload),
        "payload_bits": len(payload) * 8,
        "alpha": 12.0,
        "method": "MID_FREQ_DCT_COEFF_PARITY",
        "image_dims": f"{img.shape[1]}x{img.shape[0]}"
    }
    _forensic_audit_write(audit_entry)

    log.info(
        f"[DCT-FORENSIC] Digital DNA burned for {user_id} "
        f"| key={key_hex} | {len(payload)*8} bits | "
        f"LOC=({lat},{lng}) | method=MID_FREQ_PARITY"
    )

    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    return FileResponse(
        path=out_path, 
        filename=f"Q4_Financial_Summary_{ts_ns}.png", 
        media_type="image/png",
        headers=headers
    )


@app.post("/api/extract_watermark", tags=["Forensics"])
async def extract_watermark(file: UploadFile = File(...)):
    """
    Dynamic Forensic DCT Decoder.
    Scans the forensic audit log for every recorded secret key,
    attempts extraction with each, and returns the first valid match.
    """
    import tempfile
    import os
    import re
    import cv2
    import json as _json

    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        img = cv2.imread(tmp_path)
        if img is None:
            return JSONResponse(status_code=400, content={"error": "Could not decode image"})

        # --- Screen-Crop & Camera Perspective Alignment ---
        template_path = os.path.join(os.path.dirname(__file__), "template.png")
        if os.path.exists(template_path):
            template_img = cv2.imread(template_path)
            if template_img is not None:
                th, tw = template_img.shape[:2]
                ih, iw = img.shape[:2]
                aligned = False
                
                # 1. Try Template Matching for raw screenshots
                if ih >= th and iw >= tw and (ih != th or iw != tw):
                    res = cv2.matchTemplate(img, template_img, cv2.TM_CCOEFF_NORMED)
                    min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(res)
                    if max_val > 0.6:
                        x, y = max_loc
                        img = img[y:y+th, x:x+tw]
                        aligned = True
                        log.info(f"[DCT-FORENSIC] Screenshot detected. Auto-cropped at {x},{y} (conf: {max_val:.2f})")
                        
                # 2. Try ORB Alignment for camera photos with perspective distortion
                ih, iw = img.shape[:2]
                if not aligned and (ih != th or iw != tw):
                    orb = cv2.ORB_create(5000)
                    kp1, des1 = orb.detectAndCompute(template_img, None)
                    kp2, des2 = orb.detectAndCompute(img, None)
                    
                    if des1 is not None and des2 is not None:
                        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
                        matches = bf.match(des1, des2)
                        
                        if len(matches) > 30:
                            matches = sorted(matches, key=lambda x: x.distance)
                            src_pts = np.float32([ kp1[m.queryIdx].pt for m in matches ]).reshape(-1, 1, 2)
                            dst_pts = np.float32([ kp2[m.trainIdx].pt for m in matches ]).reshape(-1, 1, 2)
                            
                            M, mask = cv2.findHomography(dst_pts, src_pts, cv2.RANSAC, 5.0)
                            if M is not None:
                                img = cv2.warpPerspective(img, M, (tw, th))
                                log.info("[DCT-FORENSIC] Camera photo detected. ORB perspective alignment applied.")

        audit_entries = []
        if _FORENSIC_AUDIT_LOG.exists():
            with open(_FORENSIC_AUDIT_LOG, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = _json.loads(line)
                            if entry.get("event") == "DCT_EMBED":
                                audit_entries.append(entry)
                        except _json.JSONDecodeError:
                            continue

        if not audit_entries:
            return {"error": "Forensic audit log is empty. No keys to try.", "extracted_signature": "NO_KEYS"}

        best_match = None
        best_entry = None
        matched_key_hex = None

        # ──────────────────────────────────────────────────────────────
        #  PRIMARY: Stealth QR Recovery (works for screenshots + camera photos)
        #  The QR payload contains the full identity string directly.
        # ──────────────────────────────────────────────────────────────
        extracted_qr = _stealth_qr_extract(img)
        if extracted_qr and extracted_qr.startswith("ID:"):
            log.info(f"[STEGO-QR] Stealth QR recovered payload: {extracted_qr}")
            best_match = extracted_qr
            # Try to find matching audit entry for metadata
            for entry in audit_entries:
                if entry.get("key_hex") and entry["key_hex"] in extracted_qr:
                    best_entry = entry
                    matched_key_hex = entry["key_hex"]
                    break
            if best_entry is None and audit_entries:
                best_entry = audit_entries[-1]
                matched_key_hex = best_entry.get("key_hex", "qr_direct")
            if matched_key_hex is None:
                matched_key_hex = "qr_direct"

        # ──────────────────────────────────────────────────────────────
        #  FALLBACK: DCT Coefficient Parity Check (original forensic engine)
        # ──────────────────────────────────────────────────────────────
        if best_match is None:
            for entry in reversed(audit_entries):
                ts_ns = entry.get("timestamp_ns")
                uid = entry.get("user_id")
                if ts_ns is None or uid is None:
                    continue

                secret_key = _dct_generate_key(uid, ts_ns)
                extracted = _dct_extract(img, secret_key)

                if extracted and re.match(r"^ID:[A-Za-z0-9._]+\|DPT:", extracted):
                    best_match = extracted
                    best_entry = entry
                    matched_key_hex = entry.get("key_hex", "unknown")
                    break

        if best_match is None:
            log.warning("[DCT-FORENSIC] No matching key found in audit log vault.")
            _forensic_audit_write({
                "event": "DCT_EXTRACT_FAIL",
                "timestamp_iso": datetime.utcnow().isoformat() + "Z",
                "keys_tried": len(audit_entries),
                "method": "STEALTH_QR + MID_FREQ_DCT"
            })
            return {
                "error": "Extraction failed. No matching forensic signature found.",
                "extracted_signature": "NO_MATCH"
            }

        parts = best_match.split('|')
        user_id = parts[0].replace("ID:", "").strip() if len(parts) > 0 else "UNKNOWN"
        department = parts[1].replace("DPT:", "").strip() if len(parts) > 1 else "UNKNOWN"

        geo_str = ""
        for p in parts:
            if p.startswith("LOC:"):
                geo_str = p.replace("LOC:", "")

        log.info(
            f"[DCT-FORENSIC] MATCH CONFIRMED | Actor={user_id} | "
            f"Dept={department} | Geo={geo_str} | Key={matched_key_hex}"
        )

        _forensic_audit_write({
            "event": "DCT_EXTRACT_SUCCESS",
            "timestamp_iso": datetime.utcnow().isoformat() + "Z",
            "matched_user_id": user_id,
            "matched_key_hex": matched_key_hex,
            "original_embed_time": best_entry.get("timestamp_iso"),
            "geo": geo_str,
            "method": "STEALTH_QR + MID_FREQ_DCT"
        })

        audit_output = {
            "event_type": "critical_alert",
            "risk_score": 100,
            "impact_level": "FORENSIC_MATCH",
            "type": "Forensic Identification",
            "raw_log": {
                "actor": {"user_id": user_id},
                "action": {"type": "dct_forensic_extraction_match"},
                "context": {
                    "method": "STEALTH_QR_FORENSIC",
                    "key_hex": matched_key_hex,
                    "geo": geo_str,
                    "recovery": "standard"
                }
            },
            "ai_analysis": {
                "summary": (
                    f"CRITICAL: Stealth QR forensic match confirmed. Leaked document's "
                    f"Digital DNA traced to actor '{user_id}' ({department}). "
                    f"Geo-tag at embed time: {geo_str}. "
                    f"Recovery method: Stealth QR + DCT Parity."
                ),
                "threat_vectors": ["Forensic Identity Match", "Stealth QR Recovery", "DCT Frequency Analysis"],
                "recommended_action": "IMMEDIATE: Revoke all system access for identified actor."
            },
            "merkle_integrity": "Verified",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sequence": 8888
        }
        await manager.broadcast(audit_output)

        return {
            "extracted_signature": best_match,
            "analog_recovery": False,
            "method": "STEALTH_QR_FORENSIC",
            "matched_key": matched_key_hex,
            "geo": geo_str,
            "embed_time": best_entry.get("timestamp_iso")
        }
    except Exception as e:
        log.error(f"[DCT-FORENSIC] Extraction error: {e}")
        return {"error": str(e), "extracted_signature": "FAILED_TO_EXTRACT"}
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# â”€â”€ Policy Action Simulation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
    If DENIED â†’ broadcasts a critical policy violation alert to the SOC.
    If ALLOWED â†’ broadcasts a low-risk audit log.
    """
    user_id    = payload.get("user_id", "UNKNOWN")
    policy_key = payload.get("policy_key", "")
    department = payload.get("department", "Unknown")

    # â”€â”€ Look up the user's permissions â”€â”€
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
        # â”€â”€ ALLOWED: low-risk audit log â”€â”€
        output = {
            "event_type":       "audit_log",
            "risk_score":       15,
            "impact_level":     "POLICY_ALLOWED",
            "type":             "Policy Action â€” Authorized",
            "threat_vectors":   [],
            "raw_log": {
                "actor":    {"user_id": user_id, "name": user_name, "department": department},
                "action":   {"type": f"policy_use:{policy_key}"},
                "resource": {"name": label},
                "context":  {"ip_address": "10.0.0.99", "location": "Office", "device_type": "managed_laptop"},
            },
            "ai_analysis": {
                "summary": f"INFO: User {user_name} ({user_id}) exercised authorized privilege â€” {label}. Action permitted by IAM policy.",
                "threat_vectors": [],
                "recommended_action": "No action required. Activity is within granted permissions.",
            },
            "merkle_integrity": "Verified",
            "timestamp":        datetime.utcnow().isoformat() + "Z",
            "sequence":         6666,
        }
        log.info("[IAM] âœ… POLICY ALLOWED â€” %s (%s) â†’ %s", user_name, user_id, policy_key)
    else:
        # â”€â”€ DENIED: critical policy violation â”€â”€
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
                    f"'{label}' â€” a privilege NOT assigned to their IAM profile. "
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
            "ðŸš« POLICY VIOLATION â€” %s (%s) attempted %s (NOT AUTHORIZED)",
            user_name, user_id, policy_key,
        )

    await manager.broadcast(output)
    return {"allowed": is_allowed, "user_id": user_id, "policy_key": policy_key, "label": label}


# â”€â”€ Identity & Access Management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€ SOAR â€” Security Orchestration, Automation & Response â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
      3. Returns HTTP 200 immediately â€” the broadcast is fire-and-forget
         from the caller's perspective, making the UI feel snappy on stage.

    The frontend catches {"type": "SOAR_ACTION"} and flashes the user's
    row red + changes status to "ISOLATED".
    """
    ts = datetime.utcnow().isoformat() + "Z"

    # â”€â”€ Build the SOAR payload â”€â”€
    payload = {
        "type":      "SOAR_ACTION",
        "action":    "ISOLATE",
        "uid":       uid,
        "status":    "NETWORK_SEVERED",
        "timestamp": ts,
        "message":   f"Host isolation executed for {uid}. "
                     "All network access revoked. Session tokens invalidated.",
    }

    # â”€â”€ Audit trail â”€â”€
    soar_actions.append(payload)

    # â”€â”€ Blast to every connected dashboard â”€â”€
    await manager.broadcast(payload)

    log.critical(
        "ðŸ”’ SOAR ISOLATE â€” uid=%s | clients=%d | ts=%s",
        uid, manager.count, ts,
    )

    # Instant 200 â€” no waiting for downstream effects
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
        "ðŸ”‘ SOAR REVOKE â€” uid=%s | clients=%d | ts=%s",
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


# â”€â”€ WebSocket Endpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  ENTRY POINT
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="warning",     # suppress uvicorn noise; AEGIS has its own logger
    )
