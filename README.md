# AI-Based Intrusion Detection System (IDS)
## Graduation Project — Architecture & Developer Guide

---

## 1. SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────┐
│                  DESKTOP FRONTEND                        │
│              (CustomTkinter, Python)                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │Dashboard │ │  PCAP    │ │Real-Time │ │  Alerts  │  │
│  │  Screen  │ │ Analysis │ │ Monitor  │ │  Screen  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │
│       └─────────────┴─────────────┴────────────┘        │
│                    API Client (httpx)                    │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP/REST (localhost)
┌───────────────────────▼─────────────────────────────────┐
│                   FASTAPI BACKEND                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ /analyze │ │/realtime │ │ /alerts  │ │ /stats   │  │
│  │  (pcap)  │ │  (start) │ │          │ │          │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │
│       └─────────────┴─────────────┴────────────┘        │
│                   Service Layer                          │
│     PCAPService  |  CaptureService  |  AlertService     │
└───────────────────────┬─────────────────────────────────┘
                        │ Python function calls
┌───────────────────────▼─────────────────────────────────┐
│                   ML ENGINE LAYER                        │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Step 1: Anomaly Detection (Isolation Forest)    │   │
│  │     ↓  if anomalous                              │   │
│  │  Step 2: Attack Classification (Random Forest)   │   │
│  │     ↓  if confidence < threshold                 │   │
│  │  Step 3: Mark as SUSPICIOUS / UNKNOWN            │   │
│  └──────────────────────────────────────────────────┘   │
│                  Feature Extractor                       │
│                  Model Store (.joblib)                   │
└─────────────────────────────────────────────────────────┘
```

### Detection Pipeline (3-Stage Logic)
```
Network Traffic
      │
      ▼
[Feature Extraction]
      │
      ▼
[Stage 1: Anomaly Detection]  ← Isolation Forest (unsupervised)
      │
    NORMAL?──────────────────────► Label: BENIGN, done.
      │
    ANOMALOUS
      │
      ▼
[Stage 2: Attack Classification] ← Random Forest (supervised, CICIDS2017)
      │
    confidence >= threshold? ────► Label: <AttackType>, done.
      │
    confidence < threshold?
      │
      ▼
[Stage 3: Unknown/Suspicious]  ── Label: SUSPICIOUS_UNKNOWN
```

---

## 2. ASSUMPTIONS

1. Backend and frontend run on the **same Windows machine** — communication is via `localhost`.
2. CICIDS2017 dataset provides the labeled flow features for training.
3. Traffic capture uses **scapy** (raw packets) or **CICFlowMeter** output (pre-extracted flows).
4. Models are trained offline and saved as `.joblib` files — the backend loads them at startup.
5. Real-time capture requires running with **administrator privileges** on Windows.
6. The confidence threshold for classification defaults to **0.70** (configurable).
7. PCAP analysis uses pre-extracted features via a CICFlowMeter-compatible parser.

---

## 3. FOLDER STRUCTURE

```
ids_project/
│
├── frontend/                     # CustomTkinter Desktop App
│   ├── main.py                   # App entry point, launches CTk window
│   ├── app.py                    # Root CTk app class, navigation manager
│   ├── screens/
│   │   ├── dashboard.py          # Stats overview, recent alerts, charts
│   │   ├── pcap_analysis.py      # Upload PCAP, run analysis, show results
│   │   ├── realtime_monitor.py   # Start/stop capture, live feed
│   │   └── alerts.py             # Alerts history, filter, export
│   ├── components/
│   │   ├── sidebar.py            # Navigation sidebar
│   │   ├── alert_card.py         # Reusable alert display widget
│   │   ├── stat_card.py          # Reusable stat display widget
│   │   └── traffic_table.py      # Reusable traffic data table
│   └── utils/
│       ├── api_client.py         # All HTTP calls to FastAPI backend
│       └── config.py             # Frontend config (API URL, theme, etc.)
│
├── backend/                      # FastAPI REST API
│   ├── main.py                   # FastAPI app creation, router registration
│   ├── config.py                 # Backend settings (ports, thresholds, paths)
│   ├── routers/
│   │   ├── analyze.py            # POST /analyze/pcap
│   │   ├── realtime.py           # POST /realtime/start, /stop
│   │   ├── alerts.py             # GET /alerts, DELETE /alerts/{id}
│   │   └── stats.py              # GET /stats/summary
│   ├── services/
│   │   ├── pcap_service.py       # Parse PCAP → extract flows → run ML
│   │   ├── capture_service.py    # Manage live capture sessions
│   │   ├── alert_service.py      # Store/retrieve alerts (SQLite)
│   │   └── detection_service.py  # Calls ML engine, wraps 3-stage pipeline
│   ├── models/                   # Pydantic request/response schemas
│   │   ├── flow.py               # NetworkFlow schema
│   │   ├── alert.py              # Alert schema
│   │   └── result.py             # DetectionResult schema
│   └── utils/
│       ├── database.py           # SQLite connection via SQLAlchemy
│       └── logger.py             # Structured logging setup
│
├── ml_engine/                    # ML Training & Inference Layer
│   ├── predictor.py              # Main inference class (used by backend)
│   ├── preprocessing/
│   │   ├── feature_extractor.py  # Raw PCAP/flow → feature vector
│   │   ├── feature_names.py      # Canonical list of 78 CICIDS features
│   │   └── normalizer.py         # Scaler fit/transform
│   ├── models/
│   │   ├── anomaly_model.py      # Isolation Forest wrapper
│   │   ├── classifier_model.py   # Random Forest wrapper
│   │   └── model_store.py        # Load/save .joblib files
│   └── training/
│       ├── train_anomaly.py      # Script: train isolation forest
│       ├── train_classifier.py   # Script: train random forest on CICIDS2017
│       └── evaluate.py           # Evaluation metrics, confusion matrix
│
├── shared/                       # Shared constants between layers
│   ├── attack_labels.py          # CICIDS2017 attack class names
│   └── constants.py              # Confidence threshold, feature count, etc.
│
├── data/                         # (gitignored) — your local data
│   ├── cicids2017/               # Raw CICIDS2017 CSV files go here
│   ├── models/                   # Saved .joblib model files
│   └── alerts.db                 # SQLite database
│
├── docs/
│   └── architecture.md           # This file (extended)
│
├── requirements.txt
├── start_backend.bat             # Windows: start FastAPI server
├── start_frontend.bat            # Windows: start desktop app
└── README.md
```

---

## 4. IMPLEMENTATION PHASES

### Phase 1 — Foundation & Skeleton (Current Phase)
- [x] Project folder structure
- [x] CustomTkinter app skeleton with navigation
- [x] FastAPI backend skeleton with placeholder routes
- [x] API client in frontend
- [x] Shared constants and schemas
- [ ] SQLite database setup
- [ ] `.bat` launchers for Windows

**Goal:** App launches, screens navigate, API responds with mock data.

---

### Phase 2 — ML Engine Setup
- [ ] Define the 78 feature names from CICIDS2017
- [ ] Write `feature_extractor.py` for flow → vector mapping
- [ ] Write `normalizer.py` with StandardScaler
- [ ] Implement `anomaly_model.py` (Isolation Forest)
- [ ] Implement `classifier_model.py` (Random Forest)
- [ ] Write `predictor.py` — the 3-stage pipeline logic
- [ ] Test predictor with dummy feature vectors

**Goal:** ML pipeline runs end-to-end with fake data, returns proper result objects.

---

### Phase 3 — Model Training
- [ ] Download CICIDS2017 CSVs (Friday, Tuesday, etc.)
- [ ] Write `train_anomaly.py` — fit and save Isolation Forest
- [ ] Write `train_classifier.py` — clean CICIDS data, train RF, save model
- [ ] Write `evaluate.py` — classification report, confusion matrix
- [ ] Save models to `data/models/`

**Goal:** Real trained models saved to disk, predictor loads and uses them.

---

### Phase 4 — PCAP Analysis Pipeline
- [ ] Implement `pcap_service.py` using scapy for basic flow extraction
- [ ] Wire `POST /analyze/pcap` → pcap_service → detection_service → ML
- [ ] Connect PCAP Analysis screen to API
- [ ] Show results in `traffic_table.py`

**Goal:** User uploads PCAP, sees per-flow detection results in the UI.

---

### Phase 5 — Real-Time Capture
- [ ] Implement `capture_service.py` with scapy AsyncSniffer
- [ ] Wire `POST /realtime/start` and `/stop`
- [ ] Stream results back (polling or WebSocket)
- [ ] Connect Real-Time Monitor screen

**Goal:** Live capture runs, results appear in the UI in near-real-time.

---

### Phase 6 — Alerts & Dashboard
- [ ] SQLite alerts persistence via `alert_service.py`
- [ ] `GET /alerts` with filter support
- [ ] Populate Dashboard with real stats
- [ ] Alert cards with severity coloring

**Goal:** Full working loop from detection to persisted alert to dashboard.

---

### Phase 7 — Polish & Packaging
- [ ] Error handling, loading states, timeouts
- [ ] Export alerts to CSV
- [ ] PyInstaller `.exe` packaging
- [ ] Final UI cleanup
- [ ] Project report / demo prep

---

## 5. TECH STACK SUMMARY

| Layer | Technology |
|---|---|
| Desktop UI | CustomTkinter (Python) |
| HTTP Client | httpx (sync) |
| Backend API | FastAPI + Uvicorn |
| Database | SQLite + SQLAlchemy |
| Data Validation | Pydantic v2 |
| Anomaly Detection | scikit-learn Isolation Forest |
| Classification | scikit-learn Random Forest |
| Model Persistence | joblib |
| Packet Capture | scapy |
| Feature Extraction | Custom + CICFlowMeter-inspired |
| Packaging | PyInstaller |

---
