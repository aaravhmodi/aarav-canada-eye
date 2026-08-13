# OSINT Canada Platform

**Live dashboard:** https://aaravhmodi-aarav-canada-eye-dashboardapp-5jx9vy.streamlit.app/

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
| `CANLII_API_KEY` / `CANLII_KEY` | Optional | Court-case collection (free key, see [collectors/counterfeit_sources.py](collectors/counterfeit_sources.py)) |

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

## MISP setup (local Docker instance)

`docker-compose.yml`'s `misp` service previously used env var names (`MISP_ADMIN_EMAIL`/
`MISP_ADMIN_PASSPHRASE`) the [misp-core image doesn't actually recognize](https://github.com/MISP/misp-docker/blob/master/docker-compose.yml)
— they were silently ignored — and had no database service for it to connect to, so it could
never start (`ERROR 2005: Unknown server host 'db'`). Now fixed: `misp-db` (MariaDB) +
`misp-redis` (password-protected Redis, separate from the project's own `redis` service) +
corrected env var names on `misp` itself.

It also auto-provisions its own admin API key from `.env`'s `MISP_KEY` (via `ADMIN_KEY`), so
there's no manual "log into the UI and click Add Auth Key" step:

```bash
# Generate a key and put it in .env, then bring the stack up
python -c "import secrets; print(secrets.token_hex(20))"   # copy into MISP_KEY in .env
# set MISP_URL=https://localhost in .env too
docker-compose up -d misp-db misp-redis misp
```

First boot takes 3-5 minutes (DB migrations, GPG key generation, taxonomy/galaxy/warninglist
imports) — watch with `docker-compose logs -f misp`. Once it's up, `push_actor_profile()`
authenticates with that same key immediately; no UI interaction needed. `config/settings.yaml`'s
`misp.verify_ssl` is set to `false` by default because this local instance uses a self-signed
cert — set it back to `true` if you point `MISP_URL` at a real instance with a valid cert.

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

## How it works (technical detail)

Two independent pipelines sharing one Postgres database, one Celery scheduler, and one
Streamlit dashboard.

### 1. Threat Actor Profiler

**Collection** (`collectors/`) — each source returns `{source_url, source_type, raw_text, title?}` dicts:
- [`rss_collector.py`](collectors/rss_collector.py) — `feedparser` over 4 general threat blogs (ESET, BleepingComputer, Krebs, Threatpost)
- [`ca_specific.py`](collectors/ca_specific.py) — CCCS's alerts + news RSS feeds (see `config/settings.yaml` → `cccs:`)
- [`paste_collector.py`](collectors/paste_collector.py) — async `httpx`/BeautifulSoup scrape of pastebin.com and paste.ee recent-paste listings
- [`tor_collector.py`](collectors/tor_collector.py) — SOCKS5-via-Tor scraper for `.onion` sources; off by default

**IOC extraction** ([`processing/ioc_extractor.py`](processing/ioc_extractor.py)):
- `iocextract` pulls IPs/URLs/hashes/emails via regex; IPs are then validated through Python's `ipaddress` module, since `iocextract` false-positives on bare timestamps like `04:26:40` as IPv6 addresses
- Custom regexes for CVE IDs and MITRE ATT&CK technique IDs, anchored (`\bT1\d{3}(?:\.\d{3})?\b`) so arbitrary `Txxxx`-shaped strings don't match
- Domains are derived from extracted URLs via `urlparse`, not returned raw — MISP's `domain` attribute type needs a bare hostname, not a full URL
- spaCy NER (`en_core_web_sm` by default, `en_core_web_trf` opt-in) extracts ORG/GPE/PERSON entities
- `canada_relevant` uses word-boundary regex matching against the configured keyword list — not naive substring matching, which used to false-positive on things like "cra" inside "cracked"

**Clustering** ([`processing/clusterer.py`](processing/clusterer.py)): builds a per-document fingerprint (its IOCs + first 500 chars of text) → embeds with `sentence-transformers` (`all-MiniLM-L6-v2`) → L2-normalizes → DBSCAN (cosine metric, `eps=0.45`, `min_samples=1`) → merges each cluster into an actor profile (union of IPs/domains/hashes/TTPs/orgs, incident count, first/last seen). `dbscan_eps`/`dbscan_min_samples` are deliberately loosened from stricter defaults (0.3/2) so low-volume runs still surface actor profiles instead of discarding everything as DBSCAN noise — see the tradeoff note in `config/settings.yaml`. The actor's `actor_label` is a SHA1 hash of its sorted IOCs, falling back to its source-doc URLs when a cluster has no IOCs at all (otherwise every IOC-less cluster would hash to the same empty-string label and collide).

**Enrichment** ([`integrations/enrichment.py`](integrations/enrichment.py)): Shodan + AbuseIPDB lookups per IP (capped at 25/run), results stored in `IOC.enrichment` (JSON).

**MISP push** ([`integrations/misp_client.py`](integrations/misp_client.py)): builds a `MISPEvent` per actor with attributes (`ip-dst`, `domain`, `md5`/`sha1`/`sha256` by hash length, TTPs as text), pushes via PyMISP, stores the returned event UUID on the actor profile.

### 2. Counterfeit Currency Pattern Tracking

**Collection** ([`collectors/counterfeit_sources.py`](collectors/counterfeit_sources.py)):
- **RCMP stats** — scrapes the live RCMP page's 6 real HTML tables (national totals, by-denomination, by-value, by-province, by-production-method, coins) via `pandas.read_html`, matched by column name rather than position so it survives the page being reordered
- **Bank of Canada** — narrative context page, HTML-stripped, stored as a `RawDocument` like the threat-intel sources (feeds the NLP/keyword pipeline for context, not structured stats)
- **CanLII** — official REST API (needs a manually-issued free key, see below); fetches the real case-database list, uses the live full-text search endpoint with CanLII query syntax, filters by configured jurisdictions, dedupes results, then hydrates each case through the documented metadata endpoint. If search returns nothing, it falls back to recent-database browse and title filtering.

**Pattern analysis** ([`processing/counterfeit_analyzer.py`](processing/counterfeit_analyzer.py)): aggregates by year/province/denomination, ranks top provinces/denominations by volume, flags anomaly years via z-score against a trailing mean (>2σ), and correlates incident volume against court-case counts per province (enforcement-gap detection).

**Banknote CNN** ([`processing/banknote_cnn.py`](processing/banknote_cnn.py)): a real, trainable PyTorch conv net (3 conv blocks, two heads — binary genuine/counterfeit classifier + 5-way security-feature presence classifier). See the **CNN accuracy caveat** below — it's trained on synthetic data only.

**Insights** ([`processing/insights.py`](processing/insights.py)): turns the pattern-analysis output into severity-tagged, specific statements (anomaly alerts, dominant-province/denomination callouts, enforcement gaps) — surfaced in the dashboard's "Key Insights" panel so the numbers translate into "do this next," not just tables to interpret yourself.

### 3. Storage ([`storage/models.py`](storage/models.py))

Postgres via SQLAlchemy: `RawDocument` / `IOC` / `ActorProfile` for threat intel; `CounterfeitStat` / `CourtCase` / `BanknoteScan` for the currency side. `save_iocs()` dedupes by `(ioc_type, value)` per document — a repeat sighting bumps `hit_count`/`last_seen` instead of inserting a duplicate row.

### 4. Orchestration

- [`main.py`](main.py) — one-shot: runs the full threat-intel pipeline, then the full counterfeit pipeline, each wrapped in try/except with `session.rollback()` on failure so one pipeline's error can't poison the other's DB transaction.
- [`tasks/celery_app.py`](tasks/celery_app.py) — same logic, scheduled: hourly RSS, every-30-min pastes, hourly CA sources, clustering every 6h, daily counterfeit stats — via Celery with a Redis broker.

### 5. Dashboard ([`dashboard/app.py`](dashboard/app.py))

Streamlit, two tabs (Threat Actors / Counterfeit Currency). The dark theme is two layers: CSS injection for custom elements (hero header, insight cards, callouts) *and* [`.streamlit/config.toml`](.streamlit/config.toml) for native widgets — `st.dataframe` renders its grid on a `<canvas>` element that only reads colors from that config file, not from injected CSS, so both layers are needed for a consistent look. Threat tab: sidebar filters, metrics, the insights panel, actor table with drill-down, MISP deep link, source-mix chart. Counterfeit tab: metrics, insights panel, national trend chart, province/denomination breakdown tables, court-case table, and the banknote scanner (upload an image or generate a synthetic sample, then run CNN inference).

### 6. Infra (`docker-compose.yml`)

`postgres` (host port 5433) and `redis` (host port 6380) for this app — both remapped off their defaults to avoid colliding with other local services; `misp` + `misp-db` (MariaDB) + `misp-redis` (dedicated, password-protected) for MISP, with the admin API key auto-provisioned from `.env`'s `MISP_KEY`; optional `tor` proxy container; `worker`/`beat`/`dashboard` containers for a fully containerized deployment.

---

## Data sources (counterfeit-currency pipeline) — verified 2026-08-08

| Source | What it provides | Status |
|---|---|---|
| [RCMP counterfeit stats](https://rcmp.ca/en/forensic-science-and-identification-services/national-forensic-laboratory-services/statistics-pertaining-counterfeit-canadian-currency) | Real HTML tables: national/provincial/denomination counts 2014–2025, production method | **Live, scraped** |
| [Bank of Canada](https://www.bankofcanada.ca/rates/banking-and-financial-statistics/statistics-on-the-counterfeiting-of-canadian-bank-notes-formerly-b4/) | Narrative context (defers actual figures to RCMP) | **Live, scraped** (as NLP context, not structured stats) |
| [CanLII](https://www.canlii.org) | Court cases citing counterfeit-currency offences (Criminal Code s.448–462) | **Requires a free API key, requested manually** — email CanLII's [feedback form](https://www.canlii.org/en/feedback/feedback.html) describing your project; there's no self-serve signup, they issue it manually. Set `CANLII_API_KEY` or `CANLII_KEY`. Uses API full-text search plus case metadata; unauthenticated public-site scraping is deliberately avoided. |
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
