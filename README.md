# OSINT Canada Platform

Two pipelines sharing one collection/storage/dashboard framework:

1. **Threat Actor Profiler** — collects from RSS feeds, paste sites, and Canadian government
   sources, extracts IOCs, clusters them into actor profiles, and pushes results to MISP.
2. **Counterfeit Currency Pattern Tracking** — pulls real published statistics from the RCMP
   (national/provincial/denomination counterfeit-note counts), Bank of Canada context, and
   CanLII court case metadata, then flags year-over-year anomalies. Includes a CNN for
   banknote security-feature analysis — see the **CNN accuracy caveat** below before trusting
   any of its output.

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

`en_core_web_sm` (spaCy's small English model) installs automatically as part of
`requirements.txt` and is the default (`config/settings.yaml` → `nlp.spacy_model`). It's
fast but less accurate than the transformer model. If you want that instead:

```bash
pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_trf-3.7.3/en_core_web_trf-3.7.3-py3-none-any.whl
```
then set `nlp.spacy_model: en_core_web_trf` in `config/settings.yaml`. `get_nlp()` in
`processing/ioc_extractor.py` falls back to `en_core_web_sm` automatically if the configured
model isn't installed, so a missing model no longer crashes the pipeline — it just logs a
warning and runs less accurately.

**2. Configure environment**

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string (see note below re: port 5433) |
| `REDIS_URL` | Yes | Redis connection string |
| `MISP_URL` / `MISP_KEY` | Optional | MISP instance for threat sharing |
| `SHODAN_API_KEY` | Optional | IP enrichment |
| `VT_API_KEY` | Optional | Hash enrichment |
| `ABUSEIPDB_KEY` | Optional | IP reputation |
| `CANLII_API_KEY` | Optional | Court-case collection (free key, see [collectors/counterfeit_sources.py](collectors/counterfeit_sources.py)) |

> **Port note:** `docker-compose.yml` publishes Postgres on host port **5433** (not the
> default 5432) because a lot of dev machines already have a local Postgres bound to 5432,
> which makes the container fail to start with "port is already allocated". If you're running
> `main.py`/the dashboard locally against the Docker stack, point `DATABASE_URL` at
> `localhost:5433`. The `worker`/`beat`/`dashboard` *containers* ignore your `.env`'s
> `DATABASE_URL`/`REDIS_URL` and instead use the `postgres`/`redis` service hostnames directly
> (set via `environment:` in `docker-compose.yml`) — inside the compose network, `localhost`
> means the container itself, not the database container, so the old config silently could
> never connect.

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

**One-shot** (collect → extract → cluster → push, both pipelines, no Celery needed):

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
Threat Intel:
  Collectors (RSS / pastes / CA gov / Tor*)
        ↓
  IOC Extractor (IPs, domains, hashes, CVEs, TTPs)
        ↓
  Enrichment (Shodan / AbuseIPDB / VirusTotal)
        ↓
  Clusterer (sentence-transformers + DBSCAN)
        ↓
  Actor Profiles → MISP + Dashboard

Counterfeit Currency:
  RCMP stats scrape + Bank of Canada context + CanLII court cases
        ↓
  Pattern Analyzer (YoY trends, z-score anomaly flags, province/denom breakdowns)
        ↓
  Dashboard (+ banknote CNN scanner, demo-only — see caveat below)
```

*Tor collection is off by default (`tor.enabled: false` in `config/settings.yaml`) — its
target list (`collectors/tor_collector.py` → `ONION_TARGETS`) ships empty; populate it and
flip the flag on to use it.

See [collectors/](collectors/), [processing/](processing/), [integrations/](integrations/) for module details.

---

## Data sources (counterfeit-currency pipeline) — verified 2026-08-08

| Source | What it provides | Status |
|---|---|---|
| [RCMP counterfeit stats](https://rcmp.ca/en/forensic-science-and-identification-services/national-forensic-laboratory-services/statistics-pertaining-counterfeit-canadian-currency) | Real HTML tables: national/provincial/denomination counts 2014–2025, production method | **Live, scraped** |
| [Bank of Canada](https://www.bankofcanada.ca/rates/banking-and-financial-statistics/statistics-on-the-counterfeiting-of-canadian-bank-notes-formerly-b4/) | Narrative context (defers actual figures to RCMP) | **Live, scraped** (as NLP context, not structured stats) |
| [CanLII](https://www.canlii.org) | Court cases citing counterfeit-currency offences (Criminal Code s.448–462) | **Requires a free API key** (`CANLII_API_KEY`) — CanLII's public search UI is behind a bot/JS challenge, so unauthenticated scraping was deliberately not attempted (it would just silently return nothing) |
| FINTRAC | No counterfeit-currency-specific typology report exists publicly; general guidance page only | Not integrated as structured data — not worth scraping for this |

## CNN accuracy caveat

**There is no public dataset of genuine vs. counterfeit Canadian bank notes.** That's not a
gap I could scrape around — labeled counterfeit-detection training data is itself sensitive
for the same reason RCMP/Bank of Canada don't publish one. `processing/banknote_cnn.py`
implements a real, trainable CNN (binary classification + 5 security-feature presence heads),
but trains it on **procedurally generated synthetic images** (`generate_synthetic_demo_dataset`)
so the collect → train → infer pipeline can be demonstrated end-to-end. Its 40/40 accuracy on
held-in synthetic samples proves the *pipeline* works, not that it can detect real counterfeit
notes. Production use would need a real labeled image dataset, realistically obtained through
a partnership with RCMP/Bank of Canada forensic services, not scraped.
