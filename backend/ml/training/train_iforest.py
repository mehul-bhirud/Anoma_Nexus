"""
train_iforest.py — Aegis-Fusion Ensemble: IsolationForest on VAE Latent Space
===============================================================================
Extracts the 10-dimensional latent vector (z) from the pre-trained VAE and
trains a scikit-learn IsolationForest on it.  The forest is saved as iforest.pkl
alongside calibration stats used by the backend for risk-score mapping.

Pipeline:
  1. Load aegis_vae_model_weighted.pth (eval mode, no_grad)
  2. Load 63-dim train_tensor.pt (normal enterprise sessions)
  3. Encode → extract μ (the mean of the latent posterior — deterministic)
  4. Fit IsolationForest on the μ vectors
  5. Save iforest.pkl + calibration stats to backend/ml/models/

Usage:  python train_iforest.py
Deps:   torch, scikit-learn, joblib, numpy
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
import joblib

# ── Windows UTF-8 ─────────────────────────────────────────────────────────
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

# ── Paths ─────────────────────────────────────────────────────────────────
ROOT       = Path(__file__).parent                    # backend/ml/training/
DATA_DIR   = ROOT.parent / "data"                     # backend/ml/data/
MODELS_DIR = ROOT.parent / "models"                   # backend/ml/models/

TRAIN_TENSOR_PATH = DATA_DIR / "train_tensor.pt"
TEST_TENSOR_PATH  = DATA_DIR / "test_tensor.pt"
VAE_MODEL_PATH    = MODELS_DIR / "aegis_vae_model_weighted.pth"
IFOREST_PATH      = MODELS_DIR / "iforest.pkl"
CALIBRATION_PATH  = MODELS_DIR / "iforest_calibration.json"

# ── Architecture (must match the VAE used in main.py) ─────────────────────
INPUT_DIM  = 64
LATENT_DIM = 10


# ═══════════════════════════════════════════════════════════════════════════
#  VAE CLASS (exact copy from engine — needed to load weights)
# ═══════════════════════════════════════════════════════════════════════════

class InsiderThreatVAE(nn.Module):
    def __init__(self, input_dim: int = INPUT_DIM, latent_dim: int = LATENT_DIM):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128), nn.LeakyReLU(0.2),
            nn.Linear(128, 64),        nn.LeakyReLU(0.2),
        )
        self.fc_mu     = nn.Linear(64, latent_dim)
        self.fc_logvar = nn.Linear(64, latent_dim)

        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 64), nn.LeakyReLU(0.2),
            nn.Linear(64, 128),         nn.LeakyReLU(0.2),
            nn.Linear(128, input_dim),  nn.Sigmoid(),
        )

    def encode(self, x: torch.Tensor):
        h = self.encoder(x)
        return self.fc_mu(h), self.fc_logvar(h)

    def forward(self, x: torch.Tensor):
        mu, logvar = self.encode(x)
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        z = mu + eps * std
        recon = self.decoder(z)
        return recon, mu, logvar


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    t0 = time.perf_counter()

    print("=" * 60)
    print("  AEGIS-FUSION  Ensemble Training: IsolationForest on VAE Latent")
    print("=" * 60)

    device = torch.device("cpu")  # IForest training is CPU-only anyway

    # ── Step 1: Load VAE ──────────────────────────────────────────────
    print(f"\n[1/4] Loading VAE from {VAE_MODEL_PATH.name} ...")
    vae = InsiderThreatVAE(input_dim=INPUT_DIM, latent_dim=LATENT_DIM)
    vae.load_state_dict(torch.load(VAE_MODEL_PATH, map_location=device, weights_only=True))
    vae.eval()
    params = sum(p.numel() for p in vae.parameters())
    print(f"      {params:,} params loaded (eval mode)")

    # ── Step 2: Load tensors ──────────────────────────────────────────
    print(f"\n[2/4] Loading tensors ...")
    X_train = torch.load(TRAIN_TENSOR_PATH, map_location=device, weights_only=True)
    X_test  = torch.load(TEST_TENSOR_PATH,  map_location=device, weights_only=True)
    print(f"      train: {list(X_train.shape)}  ({X_train.shape[0]:,} normal sessions)")
    print(f"      test:  {list(X_test.shape)}   ({X_test.shape[0]:,} anomaly sessions)")

    # ── Step 3: Extract latent vectors ────────────────────────────────
    #   We use mu (the mean of q(z|x)) — deterministic and stable.
    #   No sampling noise = cleaner IForest boundaries.
    print(f"\n[3/4] Extracting {LATENT_DIM}-dim latent vectors (mu) ...")

    with torch.no_grad():
        # Process in batches to keep memory reasonable
        batch_size = 2048
        train_mus = []
        for i in range(0, X_train.shape[0], batch_size):
            batch = X_train[i:i+batch_size]
            mu, _ = vae.encode(batch)
            train_mus.append(mu.numpy())
        Z_train = np.concatenate(train_mus, axis=0)

        test_mus = []
        for i in range(0, X_test.shape[0], batch_size):
            batch = X_test[i:i+batch_size]
            mu, _ = vae.encode(batch)
            test_mus.append(mu.numpy())
        Z_test = np.concatenate(test_mus, axis=0)

    print(f"      Z_train: {Z_train.shape}  (normal latent space)")
    print(f"      Z_test:  {Z_test.shape}   (anomaly latent space)")

    # ── Step 4: Train IsolationForest ─────────────────────────────────
    #   contamination='auto' = conservative threshold (fits forest only on normals)
    #   n_estimators=200     = enough trees for 10-dim space
    #   max_samples=0.8      = subsample for diversity
    #   random_state=42      = reproducible for hackathon demos
    print(f"\n[4/4] Training IsolationForest ...")
    iforest = IsolationForest(
        n_estimators=200,
        max_samples=0.8,
        contamination='auto',
        random_state=42,
        n_jobs=-1,          # use all CPU cores
    )
    fit_t0 = time.perf_counter()
    iforest.fit(Z_train)
    fit_time = time.perf_counter() - fit_t0
    print(f"      Fitted in {fit_time:.2f}s  ({iforest.n_estimators} trees)")

    # ── Evaluate: decision_function on train vs test ──────────────────
    #   decision_function(X):
    #     - POSITIVE = normal (farther from anomaly boundary)
    #     - NEGATIVE = anomaly (inside anomaly boundary)
    #     - 0.0      = exactly on the boundary
    train_scores = iforest.decision_function(Z_train)
    test_scores  = iforest.decision_function(Z_test)

    print(f"\n      Decision function statistics:")
    print(f"        Train (normal):  mean={np.mean(train_scores):+.4f}  "
          f"std={np.std(train_scores):.4f}  "
          f"min={np.min(train_scores):+.4f}  max={np.max(train_scores):+.4f}")
    print(f"        Test  (anomaly): mean={np.mean(test_scores):+.4f}  "
          f"std={np.std(test_scores):.4f}  "
          f"min={np.min(test_scores):+.4f}  max={np.max(test_scores):+.4f}")

    # ── Calibration: Compute the percentile anchors for risk mapping ──
    #   We need two anchor points for the backend's linear scaling:
    #     safe_anchor  = train p5  (the "most normal" normal score)
    #     alert_anchor = test p75  (the "clearly anomalous" score)
    safe_anchor  = float(np.percentile(train_scores, 5))   # deep normal
    alert_anchor = float(np.percentile(test_scores, 75))    # solid anomaly

    print(f"\n      Calibration anchors:")
    print(f"        safe_anchor  (train p5):   {safe_anchor:+.4f}")
    print(f"        alert_anchor (test p75):   {alert_anchor:+.4f}")

    # ── Save artifacts ────────────────────────────────────────────────
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(iforest, IFOREST_PATH)
    print(f"\n      -> {IFOREST_PATH.name}  (IsolationForest, {iforest.n_estimators} trees)")

    calibration = {
        "safe_anchor": safe_anchor,
        "alert_anchor": alert_anchor,
        "train_decision_mean": float(np.mean(train_scores)),
        "train_decision_std": float(np.std(train_scores)),
        "test_decision_mean": float(np.mean(test_scores)),
        "test_decision_std": float(np.std(test_scores)),
        "latent_dim": LATENT_DIM,
        "input_dim": INPUT_DIM,
        "n_estimators": iforest.n_estimators,
    }
    with open(CALIBRATION_PATH, "w", encoding="utf-8") as f:
        json.dump(calibration, f, indent=2)
    print(f"      -> {CALIBRATION_PATH.name}  (calibration stats)")

    # ── Quick smoke-test: convert to risk scores ──────────────────────
    def decision_to_risk(d: float) -> int:
        """Map IForest decision_function output to 1-100 risk score.

        Math:
          normalized = (safe_anchor - d) / (safe_anchor - alert_anchor)
          risk = clamp(normalized, 0, 1) * 99 + 1

        Why this works:
          - decision_function is HIGH for normal, LOW for anomaly
          - We invert: (safe - d) grows as d drops below safe_anchor
          - Divide by range to normalize to [0, 1]
          - Scale to [1, 100]
        """
        span = safe_anchor - alert_anchor
        if abs(span) < 1e-12:
            return 50
        normalized = (safe_anchor - d) / span
        normalized = max(0.0, min(1.0, normalized))
        return max(1, min(100, int(normalized * 99 + 1)))

    train_risks = np.array([decision_to_risk(d) for d in train_scores])
    test_risks  = np.array([decision_to_risk(d) for d in test_scores])

    print(f"\n      Risk score validation:")
    print(f"        Train:  mean={np.mean(train_risks):.1f}  "
          f"median={np.median(train_risks):.0f}  "
          f"p95={np.percentile(train_risks, 95):.0f}  max={np.max(train_risks)}")
    print(f"        Test:   mean={np.mean(test_risks):.1f}  "
          f"median={np.median(test_risks):.0f}  "
          f"p25={np.percentile(test_risks, 25):.0f}  min={np.min(test_risks)}")

    # Detection rates
    for thresh in [50, 70, 85]:
        detected = int(np.sum(test_risks >= thresh))
        rate = detected / len(test_risks) * 100
        fp = int(np.sum(train_risks >= thresh))
        fpr = fp / len(train_risks) * 100
        print(f"        @threshold={thresh:>3d}:  "
              f"detect={rate:5.1f}% ({detected:,}/{len(test_risks):,})  "
              f"FP={fpr:.2f}% ({fp:,}/{len(train_risks):,})")

    elapsed = time.perf_counter() - t0
    print(f"\n{'=' * 60}")
    print(f"  ENSEMBLE TRAINING COMPLETE  ({elapsed:.1f}s)")
    print(f"  Files: {IFOREST_PATH.name}, {CALIBRATION_PATH.name}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
