# AI-Based Intrusion Detection System (IDS)

A hybrid Intrusion Detection System for Windows, combining signature/rule-based detection, machine learning (anomaly detection + supervised classification), and a honeypot. Built as a graduation project.

Everything runs locally on a single Windows machine: a CustomTkinter desktop app talks over HTTP to a FastAPI backend, which handles all detection logic.

> Note: this project outgrew its original plan significantly during development. This README describes the system as it actually is today.

## What it does

- **Rule Engine** — detects known attack patterns in real time (port scans, SYN/UDP/ICMP floods, connection bursts, suspicious ports) using live `tshark` capture.
- **PCAP / CSV Analysis** — classifies uploaded traffic captures using a RandomForest model (78 CICIDS2017 features), reporting 97.34% accuracy.
- **Real-Time ML Layer** — a second model scores live traffic every 10 seconds using a 14-feature behavioral vector (packet rates, port entropy, etc.), catching attacks the rule engine misses.
- **Honeypot** — fake SSH/Telnet/FTP services that trap brute-force attempts and log them as alerts.
- **HTTP Flood Middleware** — flags abnormal request bursts against the backend itself.

All detections converge into one alert database, tagged by detection tier: `RULE`, `HYBRID`, `AI-CLASSIFIED`, `AI-UNKNOWN`, or `TRAP`.

**Key design principle:** low confidence never defaults to "safe." Uncertain traffic is flagged as `UNKNOWN_MALICIOUS` rather than marked benign.

## Tech stack

| Layer | Technology |
|---|---|
| Desktop UI | CustomTkinter (Python) |
| HTTP Client | httpx |
| Backend API | FastAPI + Uvicorn |
| Database | SQLite + SQLAlchemy 2.0 |
| Validation | Pydantic v2 |
| ML | scikit-learn (RandomForest, IsolationForest) + joblib |
| Packet Capture | tshark (Wireshark) + Npcap |
| PCAP Feature Extraction | CICFlowMeter (headless Java) |
| Training Data | CICIDS2017 dataset |

## Requirements

Install separately before running:
- Python 3.11+
- Wireshark / tshark
- Npcap (WinPcap-compatible mode)
- Java JRE 8+ (for CICFlowMeter)

Real-time capture and the honeypot require Administrator privileges.

## Setup

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Double-click `LAUNCH_IDS.bat` to start both backend and frontend. Use `stop_ids.bat` to stop.

## About the trained models

The `data/` folder (trained `.joblib` models, training sessions, and the raw CICIDS2017 dataset) is **not included in this repository** — GitHub's 100MB file size limit doesn't allow it.

To use this project fully, you have two options:
1. **Retrain from scratch** using `ml_engine/training/train_classifier.py` and `train_anomaly.py` (requires downloading the [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) separately).
2. **Request the pre-trained models** directly — happy to share them on request.

Without the models, the system falls back to mock/random predictions (clearly logged), so the UI still runs for demo purposes.

## Project structure

```
backend/       FastAPI app (routers, services, middleware, models)
frontend/      CustomTkinter desktop app (screens, components)
ml_engine/     Offline training + PCAP inference pipeline
shared/        Shared constants and attack label/severity maps
scripts/       Real-time model training and evaluation scripts
tools/         Attack simulators (scapy) + CICFlowMeter
data/          (gitignored) trained models, datasets, local DB
model_evaluation/  Evaluation reports and charts
```

## Why not a single .exe?

A PyInstaller build was deliberately rejected — external tool dependencies (tshark, Java), CustomTkinter/scapy bundling issues, and Windows Defender false positives made it unreliable. The project ships as Windows batch launchers instead. See `DELIVERY.md` for details.
