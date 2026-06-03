# OSINT Canada Threat Actor Profiler

Collects threat intelligence from RSS feeds, paste sites, and Canadian government sources, extracts IOCs, clusters them into actor profiles, and pushes results to MISP.

## Prerequisites

- Python 3.11+
- Docker Desktop (running)

---

## Setup

**1. Clone and create virtual environment**

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
```

**2. Download spaCy model**

```bash
pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_trf-3.7.3/en_core_web_trf-3.7.3-py3-none-any.whl
```

**3. Configure environment**

Copy `.env` and fill in your API keys:

```bash
cp .env .env.local  # or edit .env directly
```

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string |
| `MISP_URL` / `MISP_KEY` | Optional | MISP instance for threat sharing |
| `SHODAN_API_KEY` | Optional | IP enrichment |
| `VT_API_KEY` | Optional | Hash enrichment |
| `ABUSEIPDB_KEY` | Optional | IP reputation |

---

## Running

### Option A — Full stack (Docker)

Spins up Postgres, Redis, Tor, MISP, Celery worker, beat scheduler, and the dashboard:

```bash
docker-compose up -d
```

Dashboard available at **http://localhost:8501**

### Option B — Infrastructure only + local Python

Start just the backing services:

```bash
docker-compose up -d postgres redis
```

Then choose how to run the Python side:

**One-shot** (collect → extract → cluster → push, no Celery needed):

```bash
python main.py
```

**Scheduled** (Celery worker + beat, runs on recurring intervals):

```bash
# In two separate terminals
celery -A tasks.celery_app worker --loglevel=info
celery -A tasks.celery_app beat --loglevel=info
```

**Dashboard only:**

```bash
streamlit run dashboard/app.py
```

---

## Architecture

```
Collectors (RSS / pastes / CA gov)
        ↓
IOC Extractor (IPs, domains, hashes, CVEs)
        ↓
Clusterer (sentence-transformers + DBSCAN)
        ↓
Actor Profiles → MISP + Dashboard
```

See [collectors/](collectors/), [processing/](processing/), [integrations/](integrations/) for module details.
