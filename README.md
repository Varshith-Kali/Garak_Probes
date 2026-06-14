# Garak Probes — AI Model Security Gatekeeper

> **Adversarial LLM security scanner with a web UI.** Runs [Garak](https://github.com/NVIDIA/garak) probes against Hugging Face models to detect jailbreaks, prompt injection, data leakage, and 20+ other vulnerability classes before a model reaches production.

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python)
![Garak](https://img.shields.io/badge/Garak-0.15.0-red)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What It Does

1. **Submit** a Hugging Face model ID via the web UI
2. **Garak** downloads the model and runs adversarial probes (jailbreaks, injection, leakage, etc.)
3. **Exploit Failure Rate (EFR)** is computed from the scan report
4. **Verdict**: `EFR > 5%` → **REJECTED** (unsafe for production), otherwise **APPROVED**

All scanning happens locally — no external API calls except model downloads from HuggingFace.

---

## Quick Start

### Prerequisites

```bash
pip install garak fastapi uvicorn jinja2 pydantic
```

### Run

```bash
python main.py
```

Open **http://127.0.0.1:8000** in your browser.

---

## Architecture

```
┌─────────────────────────────────────┐
│            Browser (UI)             │
│  FastAPI + Jinja2 + Vanilla JS      │
└────────────────┬────────────────────┘
                 │ POST /api/v1/scan
                 ▼
┌─────────────────────────────────────┐
│         app_backend.py              │
│  • Input validation (Pydantic)      │
│  • Job queue (SQLite persistence)   │
│  • Subprocess manager               │
│  • Result parser (JSONL reports)    │
└────────────────┬────────────────────┘
                 │ python -m garak
                 ▼
┌─────────────────────────────────────┐
│         Garak 0.15.0                │
│  • HF Pipeline (local inference)    │
│  • 20+ probe families               │
│  • JSONL report output              │
└─────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `main.py` | Entry point — starts Uvicorn, ensures correct Python env |
| `app_backend.py` | FastAPI app — all routes, job management, Garak subprocess |
| `templates/index.html` | Single-page UI — form, live log, results panel |
| `gatekeeper.db` | SQLite — persists scan history across restarts |
| `garak_runs/<job_id>/` | Per-scan logs and Garak JSONL reports |

---

## Supported Generators

| Target Type | Description | Speed |
|-------------|-------------|-------|
| `huggingface` | HF Pipeline — downloads & runs model locally on CPU | ~2–4 min |
| `huggingface_api` | HF Serverless Inference API — no download needed | Fast |
| `huggingface_endpoint` | Dedicated HF endpoint URL | Varies |

---

## Probe Families

| Key | Probe | OWASP | Prompts |
|-----|-------|-------|---------|
| `dan` | DAN 11.0 Ablation | LLM01 | 127 |
| `dan_wild` | DAN In-The-Wild | LLM01 | varies |
| `promptinject` | Prompt Injection Hijack | LLM01 | ~90 |
| `encoding` | Encoding Bypass (Base64/HEX/ROT13/Morse) | LLM01 | ~240 |
| `malwaregen` | Malware & Payload Generation | LLM02 | ~80 |
| `leak` | Training Data Leakage | LLM06 | ~40 |
| `continuation` | Harmful Content Continuation | LLM06 | ~40 |
| `grandma` | Social Engineering / Roleplay | LLM01 | ~30 |
| `packagehallucination` | Hallucinated Package Names | LLM09 | ~80 |
| `sysprompt` | System Prompt Extraction | LLM07 | ~10 |
| `misleading` | False Assertion / Misinformation | LLM09 | ~100 |
| `tap` | Tree of Attacks + Pruning (cached) | LLM01 | ~50 |
| `suffix` | GCG Adversarial Suffix (cached) | LLM01 | ~50 |
| `all` | Full Audit (10 probe families) | Multi | ~500 |

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Submit a scan job |
| `GET` | `/api/v1/scan/{id}/detail` | Job record as JSON |
| `GET` | `/api/v1/scan/{id}/status` | Rendered status HTML fragment |
| `GET` | `/api/v1/scan/{id}/log` | Live log HTML fragment (last 60 lines) |
| `GET` | `/api/v1/scan/{id}/progress` | `{completed, total, pct, eta_s}` JSON |
| `GET` | `/api/v1/scans` | Scan history HTML fragment |
| `GET` | `/api/v1/scans.json` | Scan history as JSON |
| `GET` | `/api/v1/meta` | App metadata, probe list, model examples |
| `GET` | `/health` | Service health + active job count |
| `GET` | `/docs` | Interactive Swagger UI |

### Example: Submit a Scan

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -d "target_type=huggingface" \
  -d "target_name=EleutherAI/pythia-70m" \
  -d "probe_name=dan" \
  -d "hf_token=hf_your_token_here"
```

---

## Governance Policy

| EFR | Verdict |
|-----|---------|
| `0%` | ✅ APPROVED — No vulnerabilities detected |
| `1–5%` | ✅ APPROVED — Low risk, monitor in production |
| `>5%` | ❌ REJECTED — Unsafe for production deployment |

The threshold is configurable via `eval_threshold` in the scan request (default `0.5`, i.e. 50% detector confidence to count as a failure).

---

## Configuration

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `GARAK_PYTHON` | Python executable for Garak subprocess | auto-detected |
| `HF_TOKEN` | HuggingFace token for higher rate limits | embedded default |
| `USE_VENDOR_GARAK` | Use `./vendor/` checkout instead of installed garak | `0` |
| `XDG_CACHE_HOME` | Model cache directory | `./.cache` |
| `XDG_CONFIG_HOME` | Garak config directory | `./.config` |

### Scan Parameters (Advanced)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `generations` | int 1–8 | `1` | Responses per prompt |
| `parallel_requests` | int 1–16 | `1` | Concurrent model calls |
| `eval_threshold` | float 0–1 | `0.5` | Detector confidence threshold |
| `max_runtime_seconds` | int | `3600` | Hard timeout per scan |
| `extended_detectors` | bool | `true` | Use full detector suite |

---

## How the Scan Works

1. **Preflight** — verifies Garak is importable and HuggingFace is reachable
2. **Subprocess launch** — `python -m garak --target_type huggingface.Pipeline ...`
   - `CREATE_NEW_PROCESS_GROUP` on Windows: scan survives server restarts
   - Stdout/stderr piped to `garak_runs/<job_id>/` log files via background threads
   - `PYTHONUNBUFFERED=1`: real-time log streaming
3. **Live polling** — UI polls `/log` and `/progress` every 2 seconds
4. **Result parsing** — `_parse_metrics()` reads the Garak JSONL report and computes EFR
5. **Verdict** — job marked Completed/Failed, SQLite updated, UI refreshes

---

## Development

```bash
# Install dependencies
pip install garak fastapi uvicorn jinja2 pydantic python-multipart

# Run in development
python main.py

# Check API docs
open http://127.0.0.1:8000/docs
```

The server uses `reload=False` intentionally — Garak scans run as detached subprocesses that must survive server restarts.

---

## License

MIT — see [LICENSE](LICENSE) for details.
