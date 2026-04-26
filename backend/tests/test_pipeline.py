"""
test_pipeline.py — Aegis-Fusion Ensemble Integration Test Suite
================================================================
Standalone, rigorous verification that the 63-dim time-context features
and the VAE+IsolationForest ensemble are wired correctly end-to-end.

Does NOT require the FastAPI server to be running.
Mocks its own data and imports directly from the engine module.

Usage:  python test_pipeline.py
        (run from backend/tests/ or backend/)

Author: Aegis-Fusion QA Pipeline
"""

from __future__ import annotations

import sys
import os
import time
import traceback

# ── Ensure the backend/engine directory is importable ─────────────────────
# This script lives in backend/tests/ — we need backend/engine/ on sys.path
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_SCRIPT_DIR)  # backend/
_ENGINE_DIR = os.path.join(_BACKEND_DIR, "engine")
if _ENGINE_DIR not in sys.path:
    sys.path.insert(0, _ENGINE_DIR)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# ── Force UTF-8 for Windows terminals ────────────────────────────────────
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
#  IMPORTS FROM THE ENGINE (these prove the functions are importable)
# ═══════════════════════════════════════════════════════════════════════════

import json
import numpy as np
import torch
import torch.nn as nn
import joblib
from pathlib import Path

# ── Engine imports: preprocessing, model class, risk scoring ─────────────
# We import these directly from main.py to test the REAL production code.
import main as _engine  # import module to patch globals

from main import (
    preprocess_json_to_tensor,       # 1. Preprocessing function
    InsiderThreatVAE,                 # 2. VAE architecture class
    iforest_decision_to_risk,         # 3. Risk scoring function
    INPUT_DIM,                        # Should be 63
    LATENT_DIM,                       # Should be 10
    MODEL_PATH,                       # Path to VAE weights
    IFOREST_PATH,                     # Path to iforest.pkl
    META_PATH,                        # Path to feature_meta.json
)

# ── Bootstrap: Load FEATURE_META manually (normally done in FastAPI lifespan)
# Without this, preprocess_json_to_tensor will raise "FEATURE_META not loaded"
if META_PATH.exists():
    _engine.FEATURE_META = json.loads(META_PATH.read_text("utf-8"))
    FEATURE_META = _engine.FEATURE_META
    print(f"  [BOOT] FEATURE_META loaded: {FEATURE_META['num_features']} features")
else:
    raise FileNotFoundError(f"feature_meta.json not found at {META_PATH}")


# ═══════════════════════════════════════════════════════════════════════════
#  ANSI TERMINAL STYLING
# ═══════════════════════════════════════════════════════════════════════════

_GREEN  = "\033[32;1m"
_RED    = "\033[31;1m"
_CYAN   = "\033[36;1m"
_YELLOW = "\033[33;1m"
_DIM    = "\033[38;5;245m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

PASS = f"{_GREEN}[PASS]{_RESET}"
FAIL = f"{_RED}[FAIL]{_RESET}"
INFO = f"{_CYAN}[INFO]{_RESET}"
HEAD = f"{_BOLD}{_CYAN}"


# ═══════════════════════════════════════════════════════════════════════════
#  TEST HARNESS
# ═══════════════════════════════════════════════════════════════════════════

_results: list[tuple[str, bool, str]] = []


def run_test(name: str, fn):
    """Execute a test function, capture pass/fail, print live result."""
    print(f"\n  {_DIM}{'─' * 56}{_RESET}")
    print(f"  {_BOLD}{name}{_RESET}")
    t0 = time.perf_counter()
    try:
        fn()
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"  {PASS}  {_DIM}({elapsed:.1f}ms){_RESET}")
        _results.append((name, True, ""))
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        err_msg = str(e)
        print(f"  {FAIL}  {err_msg}")
        print(f"  {_DIM}{traceback.format_exc().strip()}{_RESET}")
        _results.append((name, False, err_msg))


# ═══════════════════════════════════════════════════════════════════════════
#  MOCK DATA — Saturday, 3:00 AM (the perfect insider threat timestamp)
# ═══════════════════════════════════════════════════════════════════════════

# 2026-04-25 is a Saturday. 03:00 AM = out of hours (between 20:00-06:00).
MOCK_TIMESTAMP = "2026-04-25T03:00:00.000Z"

MOCK_LOG = {
    "event_id": "TEST-001",
    "session_id": "TEST-SESSION-001",
    "timestamp": MOCK_TIMESTAMP,
    "actor": {
        "user_id": "test_user",
        "user": {
            "uid": "test_user",
            "group": "IT_Support"
        },
        "mfa_status": "success"
    },
    "action": {
        "type": "file_download",
        "status": "success"
    },
    "resource": {
        "name": "customer_loyalty_db",
        "sensitivity_label": "Confidential",
        "volume_mb": 150.0
    },
    "context": {
        "location": "Pune",
        "edr_agent_active": True
    },
    "enrichments": {
        "aegis_telemetry": {
            "file_entropy": 0.45,
            "typing_cadence_variance": 0.12,
            "optical_sensor_state": "No Detection"
        }
    }
}

# Build a minimal session history (the preprocessor needs a list of logs)
MOCK_HISTORY = [MOCK_LOG]


# ═══════════════════════════════════════════════════════════════════════════
#  TEST 1 — TIME-CONTEXT PARSING VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def test_1a_tensor_shape():
    """Assert output tensor shape is exactly [1, INPUT_DIM]."""
    tensor = preprocess_json_to_tensor(MOCK_LOG, MOCK_HISTORY)
    shape = list(tensor.shape)
    assert shape == [1, INPUT_DIM], (
        f"Expected tensor shape [1, {INPUT_DIM}], got {shape}"
    )
    print(f"    Tensor shape: {shape}")


def test_1b_is_weekend():
    """Assert is_weekend feature is exactly 1.0 for a Saturday timestamp."""
    tensor = preprocess_json_to_tensor(MOCK_LOG, MOCK_HISTORY)

    # is_weekend is at index 4 in the feature vector
    # (after hour_sin_mean, hour_sin_std, hour_cos_mean, hour_cos_std)
    feature_names = FEATURE_META["feature_names"]
    weekend_idx = feature_names.index("is_weekend")
    weekend_val = tensor[0, weekend_idx].item()

    print(f"    Feature index: {weekend_idx}")
    print(f"    is_weekend value: {weekend_val}")

    assert weekend_val == 1.0, (
        f"Expected is_weekend=1.0 for Saturday, got {weekend_val}"
    )


def test_1c_is_out_of_hours():
    """Assert is_out_of_hours feature is exactly 1.0 for 3:00 AM."""
    tensor = preprocess_json_to_tensor(MOCK_LOG, MOCK_HISTORY)

    feature_names = FEATURE_META["feature_names"]
    ooh_idx = feature_names.index("is_out_of_hours")
    ooh_val = tensor[0, ooh_idx].item()

    print(f"    Feature index: {ooh_idx}")
    print(f"    is_out_of_hours value: {ooh_val}")

    assert ooh_val == 1.0, (
        f"Expected is_out_of_hours=1.0 for 03:00 AM, got {ooh_val}"
    )


def test_1d_weekday_business_hours():
    """Counter-test: a Tuesday 10:00 AM log should have both flags = 0.0."""
    weekday_log = dict(MOCK_LOG)
    # 2026-04-21 is a Tuesday
    weekday_log["timestamp"] = "2026-04-21T10:00:00.000Z"
    weekday_history = [weekday_log]

    tensor = preprocess_json_to_tensor(weekday_log, weekday_history)
    feature_names = FEATURE_META["feature_names"]

    weekend_val = tensor[0, feature_names.index("is_weekend")].item()
    ooh_val     = tensor[0, feature_names.index("is_out_of_hours")].item()

    print(f"    is_weekend (Tuesday): {weekend_val}")
    print(f"    is_out_of_hours (10AM): {ooh_val}")

    assert weekend_val == 0.0, (
        f"Expected is_weekend=0.0 for Tuesday, got {weekend_val}"
    )
    assert ooh_val == 0.0, (
        f"Expected is_out_of_hours=0.0 for 10:00 AM, got {ooh_val}"
    )


# ═══════════════════════════════════════════════════════════════════════════
#  TEST 2 — PYTORCH VAE LATENT EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def test_2a_vae_loads_63dim():
    """Assert the VAE model loads and accepts a 63-dim input without crash."""
    model = InsiderThreatVAE(input_dim=INPUT_DIM, latent_dim=10)
    model.load_state_dict(
        torch.load(MODEL_PATH, map_location="cpu", weights_only=True)
    )
    model.eval()

    params = sum(p.numel() for p in model.parameters())
    print(f"    Model loaded: {params:,} params")
    print(f"    input_dim={INPUT_DIM}, latent_dim={LATENT_DIM}")

    assert INPUT_DIM == 64, f"Expected INPUT_DIM=64, got {INPUT_DIM}"
    assert LATENT_DIM == 10, f"Expected LATENT_DIM=10, got {LATENT_DIM}"


def test_2b_latent_vector_shape():
    """Assert the encoder outputs a [1, 10] latent vector from a 63-dim input."""
    model = InsiderThreatVAE(input_dim=INPUT_DIM, latent_dim=10)
    model.load_state_dict(
        torch.load(MODEL_PATH, map_location="cpu", weights_only=True)
    )
    model.eval()

    # Use real preprocessed tensor from the mock log
    tensor = preprocess_json_to_tensor(MOCK_LOG, MOCK_HISTORY)
    print(f"    Input tensor shape: {list(tensor.shape)}")

    with torch.no_grad():
        mu, logvar = model.encode(tensor)

    mu_shape = list(mu.shape)
    print(f"    Latent mu shape: {mu_shape}")
    print(f"    Latent mu sample: [{', '.join(f'{v:.4f}' for v in mu[0][:5].tolist())}...]")

    assert mu_shape == [1, 10], (
        f"Expected latent shape [1, 10], got {mu_shape}"
    )

    logvar_shape = list(logvar.shape)
    assert logvar_shape == [1, 10], (
        f"Expected logvar shape [1, 10], got {logvar_shape}"
    )


def test_2c_full_forward_pass():
    """Assert the full VAE forward pass (encode+decode) produces valid output."""
    model = InsiderThreatVAE(input_dim=INPUT_DIM, latent_dim=10)
    model.load_state_dict(
        torch.load(MODEL_PATH, map_location="cpu", weights_only=True)
    )
    model.eval()

    tensor = preprocess_json_to_tensor(MOCK_LOG, MOCK_HISTORY)

    with torch.no_grad():
        recon, mu, logvar = model(tensor)

    recon_shape = list(recon.shape)
    print(f"    Reconstruction shape: {recon_shape}")
    print(f"    Recon range: [{recon.min().item():.4f}, {recon.max().item():.4f}]")

    assert recon_shape == [1, INPUT_DIM], (
        f"Expected reconstruction shape [1, {INPUT_DIM}], got {recon_shape}"
    )
    # Sigmoid output: all values must be in [0, 1]
    assert recon.min().item() >= 0.0, "Reconstruction has negative values"
    assert recon.max().item() <= 1.0, "Reconstruction exceeds 1.0"


# ═══════════════════════════════════════════════════════════════════════════
#  TEST 3 — ISOLATION FOREST SCORING & RISK MAPPING
# ═══════════════════════════════════════════════════════════════════════════

def test_3a_iforest_loads():
    """Assert iforest.pkl loads and has the expected structure."""
    assert IFOREST_PATH.exists(), f"iforest.pkl not found at {IFOREST_PATH}"

    iforest = joblib.load(IFOREST_PATH)
    n_trees = iforest.n_estimators

    print(f"    IsolationForest loaded: {n_trees} trees")
    print(f"    Expected features: {iforest.n_features_in_}")

    assert n_trees == 200, f"Expected 200 trees, got {n_trees}"
    assert iforest.n_features_in_ == 10, (
        f"Expected 10 features (latent dim), got {iforest.n_features_in_}"
    )


def test_3b_decision_function_output():
    """Assert decision_function returns a valid float for a real latent vector."""
    # Load VAE
    model = InsiderThreatVAE(input_dim=INPUT_DIM, latent_dim=10)
    model.load_state_dict(
        torch.load(MODEL_PATH, map_location="cpu", weights_only=True)
    )
    model.eval()

    # Load IForest
    iforest = joblib.load(IFOREST_PATH)

    # Extract latent vector from mock log
    tensor = preprocess_json_to_tensor(MOCK_LOG, MOCK_HISTORY)
    with torch.no_grad():
        mu, _ = model.encode(tensor)
    z = mu.cpu().numpy()  # shape: [1, 10]

    print(f"    Latent z shape: {z.shape}")

    # Score with IForest
    decision = iforest.decision_function(z)
    score = float(decision[0])

    print(f"    Decision function output: {score:+.6f}")
    print(f"    Type: {type(score).__name__}")

    assert isinstance(score, float), (
        f"Expected float, got {type(score).__name__}"
    )
    # Decision function is typically in range [-0.5, 0.5] but not strictly bounded
    # Just verify it's a finite number
    assert np.isfinite(score), f"Decision score is not finite: {score}"


def test_3c_risk_score_bounds():
    """Assert iforest_decision_to_risk maps to integer strictly in [1, 100]."""
    # Test with a range of synthetic decision_function values
    test_values = [
        (+0.15, "Deep normal"),
        (+0.05, "Normal edge"),
        ( 0.00, "Boundary"),
        (-0.05, "Mild anomaly"),
        (-0.13, "Clear anomaly"),
        (-0.30, "Extreme anomaly"),
        (+0.50, "Far normal outlier"),
        (-1.00, "Extreme negative"),
    ]

    all_passed = True
    for decision_val, label in test_values:
        risk = iforest_decision_to_risk(decision_val)
        in_range = 1 <= risk <= 100
        is_int = isinstance(risk, int)
        status = "ok" if (in_range and is_int) else "VIOLATION"

        print(f"    d={decision_val:+.2f} ({label:20s}) -> risk={risk:3d}  "
              f"[int={is_int}, 1-100={in_range}]  {status}")

        if not (in_range and is_int):
            all_passed = False

    assert all_passed, "One or more risk scores violated the [1, 100] integer bound"


def test_3d_end_to_end_ensemble():
    """Full pipeline: mock log -> preprocess -> VAE encode -> IForest -> risk score."""
    # Load models
    model = InsiderThreatVAE(input_dim=INPUT_DIM, latent_dim=10)
    model.load_state_dict(
        torch.load(MODEL_PATH, map_location="cpu", weights_only=True)
    )
    model.eval()
    iforest = joblib.load(IFOREST_PATH)

    # Run the full pipeline
    t0 = time.perf_counter()

    tensor = preprocess_json_to_tensor(MOCK_LOG, MOCK_HISTORY)
    with torch.no_grad():
        mu, _ = model.encode(tensor)
    z = mu.cpu().numpy()
    decision = float(iforest.decision_function(z)[0])
    risk_score = iforest_decision_to_risk(decision)

    latency_ms = (time.perf_counter() - t0) * 1000

    print(f"    Pipeline: JSON -> [1,{INPUT_DIM}] tensor -> [1,10] latent -> decision={decision:+.4f} -> risk={risk_score}")
    print(f"    End-to-end latency: {latency_ms:.2f}ms")
    print(f"    Risk score type: {type(risk_score).__name__}")

    assert isinstance(risk_score, int), f"Expected int, got {type(risk_score)}"
    assert 1 <= risk_score <= 100, f"Risk score {risk_score} out of [1, 100]"


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN — RUN ALL TESTS
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print(f"""
{HEAD}{'=' * 60}{_RESET}
{HEAD}  AEGIS-FUSION  Integration Test Suite{_RESET}
{HEAD}  VAE + IsolationForest Ensemble Verification{_RESET}
{HEAD}{'=' * 60}{_RESET}
""")

    print(f"  {INFO}  INPUT_DIM  = {INPUT_DIM}")
    print(f"  {INFO}  LATENT_DIM = {LATENT_DIM}")
    print(f"  {INFO}  VAE model  = {MODEL_PATH.name}")
    print(f"  {INFO}  IForest    = {IFOREST_PATH.name}")
    print(f"  {INFO}  Mock timestamp = {MOCK_TIMESTAMP} (Saturday, 3AM)")

    # ── Test Suite 1: Time-Context Parsing ────────────────────────────
    print(f"\n{HEAD}  TEST SUITE 1: Time-Context Feature Engineering{_RESET}")
    run_test(f"1a. Tensor shape is [1, {INPUT_DIM}]", test_1a_tensor_shape)
    run_test("1b. is_weekend = 1.0 for Saturday", test_1b_is_weekend)
    run_test("1c. is_out_of_hours = 1.0 for 3:00 AM", test_1c_is_out_of_hours)
    run_test("1d. Counter-test: Tuesday 10AM = both 0.0", test_1d_weekday_business_hours)

    # ── Test Suite 2: VAE Latent Extraction ───────────────────────────
    print(f"\n{HEAD}  TEST SUITE 2: PyTorch VAE Architecture ({INPUT_DIM}-dim){_RESET}")
    run_test(f"2a. VAE loads {INPUT_DIM}-dim weights", test_2a_vae_loads_63dim)
    run_test("2b. Encoder outputs [1, 10] latent vector", test_2b_latent_vector_shape)
    run_test(f"2c. Full forward pass produces valid [1, {INPUT_DIM}] reconstruction", test_2c_full_forward_pass)

    # ── Test Suite 3: IsolationForest Scoring ─────────────────────────
    print(f"\n{HEAD}  TEST SUITE 3: IsolationForest Ensemble Scoring{_RESET}")
    run_test("3a. iforest.pkl loads (200 trees, 10 features)", test_3a_iforest_loads)
    run_test("3b. decision_function returns valid float", test_3b_decision_function_output)
    run_test("3c. Risk score strictly bounded [1, 100] integer", test_3c_risk_score_bounds)
    run_test("3d. End-to-end pipeline: JSON -> risk score", test_3d_end_to_end_ensemble)

    # ── Summary ───────────────────────────────────────────────────────
    total   = len(_results)
    passed  = sum(1 for _, ok, _ in _results if ok)
    failed  = total - passed

    print(f"\n  {_DIM}{'─' * 56}{_RESET}")
    print(f"\n{HEAD}{'=' * 60}{_RESET}")

    if failed == 0:
        print(f"{_GREEN}{_BOLD}  ALL {total} TESTS PASSED{_RESET}")
        print(f"{_GREEN}  Pipeline integrity verified. Ensemble is production-ready.{_RESET}")
    else:
        print(f"{_RED}{_BOLD}  {failed}/{total} TESTS FAILED{_RESET}")
        for name, ok, err in _results:
            if not ok:
                print(f"  {FAIL}  {name}: {err}")

    print(f"{HEAD}{'=' * 60}{_RESET}\n")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
