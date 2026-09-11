# IDS — Delivery & Run Instructions

This document explains how to run the AI-Based Intrusion Detection System for
the viva demonstration and how to prepare the project folder for submission.

---

## 1. How to Run (Quick Start)

**Double-click `LAUNCH_IDS.bat`** in the project root.

That single launcher will:

1. Run `setup_env.bat`, which checks whether `.venv` actually works on **this**
   machine. A Python virtual environment hard-codes the absolute path of the
   interpreter that created it, so a `.venv` copied in from another PC (or
   another Windows user account) will not run there. If `.venv` is missing or
   broken, `setup_env.bat` rebuilds it automatically from whatever Python is
   installed locally and reinstalls `requirements.txt` (one-time, a few
   minutes; needs internet access and Python 3.11+ on PATH). This is what
   used to surface as "Backend Offline" with no clear explanation.
2. Open a new terminal window for the FastAPI backend (uvicorn on `:8000`).
3. Wait until the backend's `/stats/health` endpoint responds.
4. Open another terminal window for the CustomTkinter desktop frontend.

Because of step 1, the project now works whether you zip up the folder
**with or without** `.venv` — sending it without `.venv` (recommended, see
§6) just means the client's first launch takes a couple of minutes longer.

Both windows show their own logs. To stop the system, close both windows or run
`stop_ids.bat`.

If you only need the backend (for example, when testing API requests with
PowerShell or curl), run `start_backend.bat` directly. Run `start_frontend.bat`
on its own only if the backend is already up.

---

## 2. Prerequisites (must be installed on the demo machine)

The Python virtual environment in `.venv/` already contains every Python
dependency. The following components live outside Python and must be present
on the system:

| Component | Why it's needed | Installer |
|---|---|---|
| **Wireshark / tshark** | Real-time packet capture for the live monitor | https://www.wireshark.org/ |
| **Npcap** | Kernel-mode packet driver (bundled with Wireshark) | Selected during Wireshark install — enable "WinPcap API-compatible mode" |
| **Java (JRE 8+)** | Required by CICFlowMeter for PCAP feature extraction | https://adoptium.net/ |
| **Python 3.11+** | Only needed to recreate `.venv` on a fresh machine | https://www.python.org/ |

**Administrator privileges** are required for:
- Real-time packet capture (tshark needs raw socket access via Npcap)
- Running scapy demo scripts (raw packet injection)

If real-time detection produces no packets, re-launch the application from an
Administrator PowerShell:

```powershell
Start-Process -Verb RunAs cmd -ArgumentList "/k LAUNCH_IDS.bat"
```

---

## 3. Why Batch Launchers, Not a `.exe`

A PyInstaller `.exe` was considered but rejected for delivery because:

1. The application depends on external tools (tshark, Npcap, Java, CICFlowMeter)
   that cannot be bundled into a Python executable. The `.exe` would still
   require those installers, eliminating the main benefit.
2. CustomTkinter has known asset-loading issues under PyInstaller.
3. scapy ships hundreds of contrib protocol modules that PyInstaller's
   import detection misses; building a working bundle requires extensive
   manual hidden-import tuning.
4. The resulting bundle is 400–500 MB and is regularly flagged by Windows
   Defender — an unacceptable risk during a live viva demonstration.
5. The viva runs on the developer's own machine, where the `.venv` is
   already tested and proven stable. Adding a packaging layer introduces
   risk without solving any real distribution problem.

The batch launcher approach uses the validated `.venv` directly — no
repackaging, no hidden imports, no false positives.

---

## 4. First-Time Setup on a Fresh Machine

If `.venv` does not exist yet:

```powershell
cd ids_project
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Then double-click `LAUNCH_IDS.bat`.

---

## 5. Stopping the Application

| Action | Method |
|---|---|
| Normal stop | Close both terminal windows (backend + frontend) |
| Frontend hung | Close the desktop window directly |
| Backend stuck on port 8000 | Run `stop_ids.bat` |
| Force-kill everything | Task Manager → end the `python.exe` processes |

`stop_ids.bat` only kills the process bound to port 8000, so other Python
applications on the system are not affected.

---

## 6. Submission Folder — What to Include / Exclude

### Include (keep in the submission ZIP)

- `backend/`
- `frontend/`
- `ml_engine/`
- `shared/`
- `data/models/` (the trained `.joblib` files — required for ML analysis)
- `tools/` (CICFlowMeter assets if any)
- `docs/`
- `requirements.txt`
- `README.md`
- `DELIVERY.md` (this file)
- `LAUNCH_IDS.bat`, `start_backend.bat`, `start_frontend.bat`, `stop_ids.bat`, `setup_env.bat`
- `.gitignore`
- A small **sample PCAP** in `test_input/` if you want PCAP analysis to be
  demoable without the supervisor providing one

### Exclude (delete before zipping)

- `.venv/` — recreate via `pip install -r requirements.txt` on the demo machine
- `__pycache__/` folders — auto-regenerated
- `*.pyc` / `*.pyo` files
- `data/cicids2017/` — multi-GB raw dataset
- `data/uploads/` — temporary user uploads
- `data/alerts.db` — runtime database; will be regenerated empty on first run
- `logs/*.log` — runtime logs
- `test_output/` — analysis outputs from previous runs
- `dist/`, `build/`, `*.spec.bak` — old PyInstaller artefacts
- `ids_app.spec` — Phase-1 placeholder, not used in current delivery

### Quick cleanup before submission

Run this in PowerShell from the project root:

```powershell
# Remove build artefacts and caches
Remove-Item -Recurse -Force .venv, dist, build, __pycache__ -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
Get-ChildItem -Recurse -Filter *.pyc | Remove-Item -Force

# Remove runtime data
Remove-Item -Recurse -Force data\cicids2017, data\uploads -ErrorAction SilentlyContinue
Remove-Item -Force data\alerts.db -ErrorAction SilentlyContinue
Remove-Item -Force logs\*.log -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force test_output -ErrorAction SilentlyContinue
```

After cleanup the project folder should be roughly 50–100 MB
(mostly model files in `data/models/`).

---

## 7. Final Delivery Folder Structure

```
ids_project/
├── LAUNCH_IDS.bat            ← double-click to start everything
├── start_backend.bat
├── start_frontend.bat
├── stop_ids.bat
├── setup_env.bat             ← auto-repairs/creates .venv on first run
├── requirements.txt
├── README.md
├── DELIVERY.md               ← this file
├── .gitignore
│
├── backend/                  FastAPI app, routers, services, middleware
├── frontend/                 CustomTkinter desktop app
├── ml_engine/                ML pipeline (anomaly + classifier + features)
├── shared/                   constants and labels shared by both layers
│
├── data/
│   └── models/               trained .joblib files (required at runtime)
│
├── docs/                     architecture documentation
├── tools/                    CICFlowMeter assets (if bundled)
└── test_input/               optional sample PCAP for PCAP-analysis demo
```

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `LAUNCH_IDS.bat` says "Virtual environment not found" | `.venv` folder missing | Run the First-Time Setup in §4 |
| Backend window opens then closes immediately | Port 8000 already in use, or import error | Run `start_backend.bat` standalone to see the error message |
| Frontend shows "Backend Offline" | Backend not started or crashed | Check the backend window; restart with `LAUNCH_IDS.bat` |
| Real-Time Detection captures 0 packets | Not running as Administrator, or tshark missing | Re-launch as Administrator; verify `tshark --version` works |
| PCAP Analysis fails with "Java not found" | JRE not installed or not on PATH | Install JRE 8+ from adoptium.net and reopen the terminal |
| Demo scripts (scapy) fail with "Operation not permitted" | Not running as Administrator | Right-click PowerShell → Run as Administrator |
| Port 8000 stuck after crash | Orphan uvicorn process | Run `stop_ids.bat` |

---

## 9. Viva Demo Checklist

Before starting the demo, verify:

- [ ] `.venv` exists and `pip list` shows all packages from `requirements.txt`
- [ ] `tshark --version` runs successfully from a terminal
- [ ] `java -version` runs successfully from a terminal
- [ ] `data/models/` contains `anomaly_model.joblib`, `classifier_model.joblib`, `scaler.joblib`
- [ ] Wi-Fi is connected (real-time detection requires an active interface)
- [ ] Running as Administrator (for live capture and scapy demo scripts)
- [ ] `data/alerts.db` deleted for a clean alert table — OR the existing alerts cleared via the trash button in the Alerts screen

Then double-click `LAUNCH_IDS.bat` and proceed with the demonstration.
