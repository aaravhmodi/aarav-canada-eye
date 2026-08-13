"""
Counterfeit currency data sources:
- RCMP Forensic Science & Identification Services — structured stats tables (WORKING, live).
- Bank of Canada — narrative/context page, collected as a RawDocument for NLP context.
- CanLII — court cases referencing counterfeit currency offences (requires a free API key).

Verified live 2026-08-08. Government sites restructure occasionally; each function fails
soft (logs a warning, returns []) rather than crashing the whole collection run.
"""
import re
from datetime import datetime
from io import StringIO
import httpx
import pandas as pd
from loguru import logger
from config import cfg

CFG = cfg["counterfeit"]
TIMEOUT = cfg["collection"]["request_timeout"]
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINTResearch/1.0)"}


def _redact_canlii_error(error: Exception) -> str:
    """httpx includes the full request URL in HTTPStatusError messages."""
    return re.sub(r"(api_key=)[^&'\"\s]+", r"\1<redacted>", str(error))


# ── RCMP structured stats ─────────────────────────────────────────────────────

def collect_rcmp_counterfeit_stats() -> list[dict]:
    """Scrape the RCMP's 6 counterfeit-currency HTML tables (national totals, by
    denomination, by value, by province, by production method, coins) into normalized
    rows matching storage.models.CounterfeitStat."""
    url = CFG["rcmp_stats_url"]
    try:
        r = httpx.get(url, headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
        r.raise_for_status()
        tables = pd.read_html(StringIO(r.text))
    except Exception as e:
        logger.warning(f"RCMP counterfeit stats fetch failed: {e}")
        return []

    rows: list[dict] = []
    rows += _parse_national_totals(tables, url)
    rows += _parse_by_denomination(tables, url)
    rows += _parse_by_province(tables, url)
    rows += _parse_by_production_method(tables, url)
    logger.info(f"RCMP: parsed {len(rows)} counterfeit stat rows from {len(tables)} tables")
    return rows


def _find_table(tables, required_cols: list[str]):
    """Government pages reorder tables between visits — match by column name, not position."""
    for t in tables:
        cols = [str(c).lower() for c in _flatten_columns(t.columns)]
        if all(any(req in c for c in cols) for req in required_cols):
            return t
    return None


def _flatten_columns(columns):
    return [c[-1] if isinstance(c, tuple) else c for c in columns]


def _parse_national_totals(tables, url) -> list[dict]:
    t = _find_table(tables, ["year", "passed", "seized"])
    if t is None or t.shape[1] != 3:
        logger.debug("RCMP: national totals table not found/shape changed")
        return []
    out = []
    for _, row in t.iterrows():
        try:
            out.append({
                "year": int(row.iloc[0]), "province": None, "denomination": None,
                "passed": int(row.iloc[1]), "seized": int(row.iloc[2]),
                "source_url": url,
            })
        except (ValueError, TypeError):
            continue
    return out


def _parse_by_denomination(tables, url) -> list[dict]:
    # Table has columns: Year, Year.1 (passed/seized label), $5, $10, ... $1,000
    for t in tables:
        cols = list(_flatten_columns(t.columns))
        if len(cols) >= 4 and str(cols[0]).lower() == "year" and any(c.startswith("$") for c in cols):
            denom_cols = [c for c in cols if str(c).startswith("$")]
            out = []
            for _, row in t.iterrows():
                try:
                    year = int(row.iloc[0])
                    label = str(row.iloc[1]).strip().lower()  # "passed" or "seized"
                except (ValueError, TypeError):
                    continue
                for denom in denom_cols:
                    try:
                        count = int(row[denom])
                    except (ValueError, TypeError):
                        continue
                    out.append({
                        "year": year, "province": None, "denomination": denom,
                        "passed": count if "pass" in label else 0,
                        "seized": count if "seiz" in label else 0,
                        "source_url": url,
                    })
            return out
    logger.debug("RCMP: by-denomination table not found/shape changed")
    return []


def _parse_by_province(tables, url) -> list[dict]:
    for t in tables:
        cols = list(_flatten_columns(t.columns))
        if cols and "province" in str(cols[0]).lower() and t.columns.nlevels == 2:
            out = []
            years = sorted({c[0] for c in t.columns if c[0] != cols[0]})
            for _, row in t.iterrows():
                province = str(row.iloc[0]).strip()
                if province.lower() in ("total", "canada", "nan"):
                    continue  # summary row, not an actual province/territory
                for year in years:
                    try:
                        year_int = int(year)
                        passed = int(row[(year, "Passed")]) if (year, "Passed") in t.columns else 0
                        seized = int(row[(year, "Seized")]) if (year, "Seized") in t.columns else 0
                    except (ValueError, TypeError, KeyError):
                        continue
                    out.append({
                        "year": year_int, "province": str(province), "denomination": None,
                        "passed": passed, "seized": seized, "source_url": url,
                    })
            return out
    logger.debug("RCMP: by-province table not found/shape changed")
    return []


def _parse_by_production_method(tables, url) -> list[dict]:
    t = _find_table(tables, ["year", "offset", "toner"])
    if t is None:
        logger.debug("RCMP: production-method table not found/shape changed")
        return []
    out = []
    for _, row in t.iterrows():
        try:
            year = int(row.iloc[0])
        except (ValueError, TypeError):
            continue
        for col in t.columns[1:]:
            try:
                out.append({
                    "year": year, "province": None, "denomination": None,
                    "passed": int(row[col]), "seized": 0,
                    "production_method": str(col), "source_url": url,
                })
            except (ValueError, TypeError):
                continue
    return out


# ── Bank of Canada narrative page ────────────────────────────────────────────

def collect_boc_context() -> list[dict]:
    """Bank of Canada's page is prose/links (it defers actual figures to RCMP) — collected
    as a RawDocument like other sources so it flows through the existing NLP/keyword pipeline
    for context, not as structured stats."""
    url = CFG["boc_stats_page"]
    try:
        r = httpx.get(url, headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
        r.raise_for_status()
        text = re.sub(r"<[^>]+>", " ", r.text)
        text = re.sub(r"\s+", " ", text).strip()
        return [{
            "source_url": url, "source_type": "boc_gov",
            "raw_text": text[:cfg["collection"]["max_text_length"]],
        }]
    except Exception as e:
        logger.warning(f"Bank of Canada page fetch failed: {e}")
        return []


# ── CanLII court cases ───────────────────────────────────────────────────────

CANLII_BASE = "https://api.canlii.org/v1"
MAX_DATABASES_QUERIED = 15  # a single province can have a dozen+ court/tribunal databases


def _canlii_databases(api_key: str) -> list[dict]:
    """databaseId (e.g. "onca", "onsc") is NOT the same as a jurisdiction code (e.g. "on") —
    a jurisdiction has many databases. This lists all of them so callers can filter by the
    `jurisdiction` field, per https://github.com/canlii/API_documentation."""
    r = httpx.get(f"{CANLII_BASE}/caseBrowse/en/", params={"api_key": api_key}, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json().get("caseDatabases", [])


def collect_counterfeit_court_cases() -> list[dict]:
    """Pull recent case metadata from CanLII's official v1 API (https://api.canlii.org) across
    every case database in the configured jurisdictions, and keep cases whose title mentions
    counterfeiting.

    Requires a free API key — CanLII doesn't sell/self-serve one; you request it by emailing
    CanLII's feedback form (https://www.canlii.org/en/feedback/feedback.html) describing your
    project, and they issue a key manually. Set CANLII_API_KEY once you have it.

    CanLII's API is metadata-browse only (per its docs) — there is no full-text/keyword search
    parameter, so this is a title-level filter, not a full-text search; a real case that
    doesn't say "counterfeit" in its title won't be found this way. Unauthenticated scraping of
    canlii.org's search UI is not attempted: the site sits behind a JS/bot challenge (confirmed
    — plain HTTP requests get a 403 challenge page), so a scraper would silently return nothing.
    """
    api_key = CFG.get("canlii_api_key")
    if not api_key:
        logger.warning(
            "CANLII_API_KEY not set — skipping court case collection. Request a free key via "
            "https://www.canlii.org/en/feedback/feedback.html (describe your project; they "
            "issue it manually, there's no self-serve signup) and set it in .env."
        )
        return []

    try:
        all_dbs = _canlii_databases(api_key)
    except Exception as e:
        logger.warning(f"CanLII database list fetch failed: {_redact_canlii_error(e)}")
        return []

    target_jurisdictions = set(CFG["canlii_jurisdictions"])
    matching_dbs = [db for db in all_dbs if db.get("jurisdiction") in target_jurisdictions]
    if len(matching_dbs) > MAX_DATABASES_QUERIED:
        logger.info(f"CanLII: {len(matching_dbs)} databases match configured jurisdictions, querying first {MAX_DATABASES_QUERIED}")
        matching_dbs = matching_dbs[:MAX_DATABASES_QUERIED]

    cases = []
    per_db_count = max(CFG["max_cases"] // max(len(matching_dbs), 1), 5)
    for db in matching_dbs:
        db_id = db["databaseId"]
        try:
            r = httpx.get(f"{CANLII_BASE}/caseBrowse/en/{db_id}/", params={
                "api_key": api_key, "offset": 0, "resultCount": per_db_count,
            }, timeout=TIMEOUT)
            r.raise_for_status()
            for case in r.json().get("cases", []):
                title = case.get("title", "")
                if "counterfeit" not in title.lower():
                    continue
                cases.append({
                    "canlii_id": f"{db_id}:{case.get('caseId', {}).get('en', '')}",
                    "case_name": title,
                    "citation": case.get("citation"),
                    "court": db.get("name", db_id),
                    "jurisdiction": db.get("jurisdiction"),
                    "decision_date": case.get("decisionDate"),
                    "url": case.get("url"),
                })
        except Exception as e:
            logger.warning(f"CanLII collection failed for database '{db_id}': {_redact_canlii_error(e)}")
    logger.info(f"CanLII: queried {len(matching_dbs)} databases, {len(cases)} counterfeit-related cases found")
    return cases


def collect_all_counterfeit_sources() -> dict:
    """Aggregate all counterfeit-currency sources. Returns a dict (not a flat list) because
    the RCMP stats and court cases are structured records for their own tables, while the
    Bank of Canada page is a RawDocument like the threat-intel collectors."""
    return {
        "stats": collect_rcmp_counterfeit_stats(),
        "context_docs": collect_boc_context(),
        "court_cases": collect_counterfeit_court_cases(),
    }
