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
                province = row.iloc[0]
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

def collect_counterfeit_court_cases() -> list[dict]:
    """Pull recent case metadata from CanLII's official v1 API (https://api.canlii.org) for
    each configured jurisdiction and keep cases whose title mentions counterfeiting.

    Requires a free API key (apply at https://www.canlii.org/en/feedback/newAccountRequest.html,
    set CANLII_API_KEY) — CanLII does not offer full-text search on the free tier, only
    metadata browse, so this is a title/citation-level filter, not a full-text search.
    Unauthenticated scraping of canlii.org is not attempted: the site sits behind a JS/bot
    challenge (confirmed: plain HTTP requests get a 403 challenge page), so a scraper would
    silently return nothing anyway.
    """
    api_key = CFG.get("canlii_api_key")
    if not api_key:
        logger.warning(
            "CANLII_API_KEY not set — skipping court case collection. "
            "Apply for a free key at canlii.org and set it in .env to enable this source."
        )
        return []

    cases = []
    for jurisdiction in CFG["canlii_jurisdictions"]:
        db_url = f"https://api.canlii.org/v1/caseBrowse/en/{jurisdiction}/"
        try:
            r = httpx.get(db_url, params={
                "api_key": api_key,
                "resultCount": CFG["max_cases"],
            }, timeout=TIMEOUT)
            r.raise_for_status()
            for case in r.json().get("cases", []):
                title = case.get("title", "")
                if "counterfeit" not in title.lower():
                    continue
                cases.append({
                    "canlii_id": f"{jurisdiction}:{case.get('caseId', {}).get('en', '')}",
                    "case_name": title,
                    "citation": case.get("citation"),
                    "court": jurisdiction.upper(),
                    "jurisdiction": jurisdiction,
                    "decision_date": case.get("decisionDate"),
                    "url": case.get("url"),
                })
        except Exception as e:
            logger.warning(f"CanLII collection failed for jurisdiction '{jurisdiction}': {e}")
    logger.info(f"CanLII: {len(cases)} counterfeit-related cases found")
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
