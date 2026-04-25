# Aegis-Fusion (Anomalyze)

**Aegis** is an advanced, real-time **Insider Threat Detection Engine** designed to process large streams of enterprise activity logs to detect anomalous and potentially destructive user behavior.

## Features

- **Real-Time Log Ingestion**: High-velocity tracking of enterprise activity via OCSF-compliant schemas.
- **PyTorch VAE (Variational Autoencoder)**: Deep learning anomaly detection to compute real-time risk scores on behavioral feature vectors.
- **Rolling Merkle Hash Chain**: Cryptographically guarantees the order and integrity of log ingestion.
- **Ollama LLM Agent Analysis**: Asynchronous queueing of local LLM models (e.g., Llama 3) to generate human-readable threat narratives and incident summaries.
- **Next.js Real-time Dashboard**: Modern web interface using React, Framer Motion, Recharts, and WebSockets to visualize live threats and system telemetry.
- **SOC Analyst Simulator**: Streamlining high-risk alerts with actionable SOC steps.

## Architecture

1. **Backend Engine**: Python (FastAPI), PyTorch, Pandas, Asyncio.
2. **Frontend UI**: Next.js (React), TailwindCSS, Recharts.
3. **AI Pipeline**: VAE + Priority-queued Local LLM via Ollama.

## Setup

### Backend (Engine)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install fastapi uvicorn[standard] websockets torch httpx pandas
python engine/main.py
```
> The API will start on port 8000. Ensure you have [Ollama](https://ollama.com/) running locally with the `llama3` model for AI analysis.

### Frontend (Dashboard)
```bash
cd frontend
npm install
npm run dev
```
> The dashboard will start on port 3000.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
