import subprocess, sys
result = subprocess.run(
    [sys.executable, "tune_vae.py"],
    cwd=r"d:\Mehul\IIIT Pune\Cummins Hackathon\Anomalyze\backend\ml\training",
    capture_output=False,
)
sys.exit(result.returncode)
