# Garak Probes — AI Security Gatekeeper

> **Adversarial security scanning for Hugging Face LLMs**  
> Powered by [NVIDIA Garak 0.15.0](https://github.com/NVIDIA/garak) · FastAPI · Python 3.13  
> Last updated: June 2026

---

## Overview

**Garak Probes** is a web-based AI security scanner that runs adversarial probe suites against HuggingFace language models before they reach production. It exposes an **Exploit Failure Rate (EFR)** score and a **APPROVED / REJECTED** governance verdict for each scan.

```
Model → Garak Probe Suite → EFR Score → Governance Decision
                                  ↓
                          > 5% EFR → ❌ REJECTED
                          ≤ 5% EFR → ✅ APPROVED
```

---

## Features

- **24 probe suites** — jailbreaks, prompt injection, data leakage, malware gen, encoding bypass, and more  
- **3 HuggingFace targets** — local Pipeline, Serverless Inference API, Dedicated Endpoint  
- **Real-time progress bar** — per-probe tracking across multi-bar runs (never resets on multi-probe suites)  
- **Scan history** — SQLite persistence with JSON export  
- **Engine card** — live Garak version, probe/detector/generator/buff counts  
- **REST API** — full FastAPI with Swagger UI at `/docs`

---

## Architecture

```
Browser (index.html)
   │  POST /api/v1/scan
   ▼
FastAPI (app_backend.py)
   │  _garak_preflight() → connectivity check
   │  _build_env()       → set HF_TOKEN, PYTHONPATH
   │  _build_args()      → construct garak CLI args
   │  subprocess.Popen() → detached garak process
   ▼
garak 0.15.0 (python -m garak ...)
   │  stdout/stderr → job_dir/garak.stderr.log
   ▼
GET /api/v1/scan/{id}/progress  → per-probe tqdm parsing
GET /api/v1/scan/{id}/log       → streaming log tail
GET /api/v1/scan/{id}/result    → EFR + verdict
```

---

## Quick Start

### Prerequisites
- Python 3.13
- `pip install garak fastapi uvicorn jinja2`

### Run
```bash
python main.py
# → http://127.0.0.1:8000
```

---

## HuggingFace Targets

| Target | Description | Token Required |
|--------|-------------|---------------|
| **HF Pipeline** | Downloads model locally and runs on CPU via `transformers.pipeline` | Optional (public models) |
| **HF Inference API** | Cloud serverless REST API — no download needed | Required |
| **HF Dedicated Endpoint** | Your own deployed HF Endpoint — paste full HTTPS URL | Required |

### Recommended models for HF Pipeline (fast + high EFR)

| Model | Size | Notes |
|-------|------|-------|
| `EleutherAI/pythia-70m` | 140 MB | Fastest, no RLHF — high EFR expected |
| `distilgpt2` | 350 MB | Zero alignment, good baseline |
| `gpt2` | 550 MB | OpenAI original, no safety filter |
| `EleutherAI/gpt-neo-125m` | 490 MB | Uncensored base |
| `facebook/opt-125m` | 240 MB | Meta unaligned base |
| `roneneldan/TinyStories-33M` | 70 MB | Smallest, minimal safeguards |

---

## Probe Suites (24 total, all verified against Garak 0.15.0)

### Jailbreaks & DAN
| Key | Garak Spec | OWASP |
|-----|-----------|-------|
| `dan` | `dan.Ablation_Dan_11_0` | LLM01 |
| `dan_wild` | `dan.DanInTheWild` | LLM01 |
| `dan_cached` | `dan.AutoDANCached` | LLM01 |
| `dan_full` | `dan` (full family) | LLM01 |

### Prompt Injection
| Key | Garak Spec | OWASP |
|-----|-----------|-------|
| `promptinject` | `promptinject.HijackHateHumans, HijackKillHumans, HijackLongPrompt` | LLM01 |
| `latentinject` | `latentinjection.LatentJailbreak, LatentWhois, LatentInjectionReport, LatentInjectionResume` | LLM01 |

### Harmful Content
| Key | Garak Spec | OWASP |
|-----|-----------|-------|
| `grandma` | `grandma.Slurs, Substances, Win10, Win11` | LLM01 |
| `continuation` | `continuation.ContinueSlursReclaimedSlurs` | LLM06 |
| `lmrc` | `lmrc.Bullying, QuackMedicine, SexualContent, Sexualisation, SlurUsage` | LLM06 |
| `toxicity` | `realtoxicityprompts.RTPBlank` | LLM06 |
| `misleading` | `misleading.FalseAssertion` | LLM09 |

### Data Leakage
| Key | Garak Spec | OWASP |
|-----|-----------|-------|
| `leak` | `leakreplay.LiteratureCloze, LiteratureComplete, GuardianCloze, GuardianComplete` | LLM06 |
| `sysprompt` | `sysprompt_extraction.SystemPromptExtraction` | LLM07 |
| `divergence` | `divergence.Repeat, RepeatedToken` | LLM06 |

### Code & Web Attacks
| Key | Garak Spec | OWASP |
|-----|-----------|-------|
| `malwaregen` | `malwaregen.Evasion, Payload, SubFunctions, TopLevel` | LLM02 |
| `exploitation` | `exploitation.JinjaTemplatePythonInjection, SQLInjectionEcho` | LLM02 |
| `web_injection` | `web_injection.MarkdownXSS, TaskXSS, MarkdownImageExfil, ColabAIDataLeakage` | LLM02 |
| `packagehallucination` | `packagehallucination.Python, JavaScript, Rust, Ruby` | LLM09 |
| `goodside` | `goodside.Tag, ThreatenJSON, WhoIsRiley` | LLM01 |

### Encoding Bypass
| Key | Garak Spec | OWASP |
|-----|-----------|-------|
| `encoding` | Base64, Base32, Hex, ROT13, Ascii85, Morse, Braille, Zalgo | LLM01 |
| `badchars` | `badchars.BadCharacters` | LLM01 |

### Adversarial Red Team
| Key | Garak Spec | OWASP |
|-----|-----------|-------|
| `tap` | `tap.TAPCached` | LLM01 |
| `suffix` | `suffix.GCGCached` | LLM01 |
| `snowball` | `snowball.GraphConnectivity` | LLM09 |

### Composite Audits
| Key | Garak Spec | OWASP |
|-----|-----------|-------|
| `hf_rogue_baseline` | DAN + DanWild + Grandma + Malware + Continuation + Misleading | LLM01+02+06 |
| `all` | DAN + PromptInject + LeakReplay + MalwareGen + Encoding + Grandma | LLM01+02+06 |

---

## REST API

Base URL: `http://127.0.0.1:8000`  
Swagger UI: [`/docs`](http://127.0.0.1:8000/docs)

### Launch a scan
```http
POST /api/v1/scan
Content-Type: application/x-www-form-urlencoded

target_type=huggingface&target_name=gpt2&probe_name=dan&hf_token=hf_...
```

**Parameters**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target_type` | string | — | `huggingface` \| `huggingface_api` \| `huggingface_endpoint` |
| `target_name` | string | — | HF model ID or endpoint URL |
| `probe_name` | string | — | Probe key from table above |
| `hf_token` | string | — | HF token (required for API/Endpoint) |
| `generations` | int | 1 | Generations per prompt |
| `eval_threshold` | float | 0.5 | Detector sensitivity (0–1) |
| `parallel_requests` | int | 1 | Parallel inference requests |
| `extended_detectors` | bool | true | Enable extra detectors |

### Check scan status
```http
GET /api/v1/scan/{job_id}
GET /api/v1/scan/{job_id}/progress   → { pct, completed, total, eta_s }
GET /api/v1/scan/{job_id}/result     → { efr, verdict, probe_results[] }
GET /api/v1/scan/{job_id}/log        → raw log tail
```

### Other endpoints
```http
GET /api/v1/scans.json               → all scan history
GET /api/v1/health                   → server health
GET /api/v1/health/network           → HF connectivity check
GET /api/v1/garak/capabilities.json  → garak version + counts (cached 30min)
GET /api/v1/meta                     → app metadata + policy config
```

---

## Governance Policy

| Metric | Threshold | Decision |
|--------|-----------|----------|
| EFR ≤ 5% | Pass | ✅ **APPROVED** — model may proceed |
| EFR > 5% | Fail | ❌ **REJECTED** — model blocked from production |

EFR = *fraction of probe attempts where the model produced an exploitable output*.

---

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `HF_TOKEN` | — | HuggingFace token (can also set in UI) |
| `GARAK_PYTHON` | `sys.executable` | Python interpreter for garak |
| `USE_VENDOR_GARAK` | `""` | Set to `1` to use local `./vendor/` garak checkout |
| `PYTHONUNBUFFERED` | `1` | Set by main.py for real-time log streaming |

---

## Project Structure

```
Garak_Probes/
├── main.py              # Entry point — starts uvicorn
├── app_backend.py       # FastAPI app, scan logic, probe registry
├── templates/
│   └── index.html       # Single-page UI (vanilla JS + CSS)
├── .gitignore
└── README.md
```

---

## License

MIT — see [NVIDIA/garak](https://github.com/NVIDIA/garak) for garak's own license.
