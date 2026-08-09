"""
Entry point for one-shot collection + processing run (no Celery required).
Usage: python main.py
"""
import asyncio
from loguru import logger
from config import cfg
from storage.models import (
    init_db, get_session, save_iocs,
    RawDocument, CounterfeitStat, CourtCase,
)
from collectors.rss_collector import collect_rss_feeds
from collectors.paste_collector import collect_all_pastes
from collectors.ca_specific import collect_all_ca_sources
from collectors.tor_collector import collect_tor_sources
from collectors.counterfeit_sources import collect_all_counterfeit_sources
from processing.ioc_extractor import process_document
from processing.clusterer import cluster_documents
from processing.counterfeit_analyzer import aggregate_patterns, correlate_with_court_cases
from integrations.misp_client import push_actor_profile
from integrations.enrichment import enrich_ip

MAX_IPS_TO_ENRICH = 25  # cap external enrichment calls (Shodan/AbuseIPDB rate limits)


def save_doc(session, doc: dict, processed: dict) -> RawDocument:
    row = RawDocument(
        source_url=doc["source_url"],
        source_type=doc["source_type"],
        raw_text=doc["raw_text"][:50000],
        canada_relevant=processed["canada_relevant"],
    )
    session.add(row)
    session.flush()  # assigns row.id so save_iocs() can set document_id
    return row


def run_threat_intel_pipeline(session) -> list[dict]:
    logger.info("Collecting threat-intel sources...")
    rss_docs = collect_rss_feeds()
    ca_docs = collect_all_ca_sources()
    paste_docs = asyncio.run(collect_all_pastes())
    tor_docs = collect_tor_sources() if cfg["tor"]["enabled"] else []

    all_docs = rss_docs + ca_docs + paste_docs + tor_docs
    logger.info(f"Collected {len(all_docs)} total documents")

    processed = []
    ioc_rows_saved = 0
    for doc in all_docs:
        p = process_document(doc)
        row = save_doc(session, doc, p)
        ioc_rows_saved += save_iocs(session, row, p["iocs"])
        if p["canada_relevant"]:
            processed.append(p)

    session.commit()
    logger.info(f"CA-relevant: {len(processed)} documents, {ioc_rows_saved} new IOCs persisted")

    _enrich_recent_ips(session)

    profiles = cluster_documents(processed)
    logger.info(f"Built {len(profiles)} actor profiles")

    for profile in profiles:
        logger.info(f"  Actor: {profile['actor_label']} — {profile['incident_count']} incidents, "
                    f"{len(profile['ips'])} IPs, {len(profile['domains'])} domains")
        push_actor_profile(profile)

    return profiles


def _enrich_recent_ips(session):
    """Shodan/AbuseIPDB enrichment was previously defined but never called anywhere.
    Filtering "enrichment is empty" is done in Python, not SQL — plain JSON columns don't
    support equality comparisons in Postgres (only JSONB does), so `IOC.enrichment == {}`
    would raise "operator does not exist: json = json" at query time."""
    from storage.models import IOC
    candidates = (
        session.query(IOC)
        .filter_by(ioc_type="ip")
        .order_by(IOC.id.desc())
        .limit(MAX_IPS_TO_ENRICH * 4)
        .all()
    )
    unenriched = [ioc for ioc in candidates if not ioc.enrichment][:MAX_IPS_TO_ENRICH]
    if not unenriched:
        return
    logger.info(f"Enriching {len(unenriched)} IPs...")
    for ioc in unenriched:
        result = enrich_ip(ioc.value)
        if result:
            ioc.enrichment = result
            if result.get("is_canadian"):
                ioc.is_canadian = True
    session.commit()


def run_counterfeit_pipeline(session):
    """Collect RCMP counterfeit stats + court cases, persist them, and compute pattern
    trends. See collectors/counterfeit_sources.py and processing/counterfeit_analyzer.py."""
    logger.info("Collecting counterfeit-currency sources...")
    sources = collect_all_counterfeit_sources()

    for row in sources["stats"]:
        session.add(CounterfeitStat(**row))
    for doc in sources["context_docs"]:
        p = process_document(doc)
        save_doc(session, doc, p)
    for case in sources["court_cases"]:
        existing = session.query(CourtCase).filter_by(canlii_id=case["canlii_id"]).first()
        if not existing:
            session.add(CourtCase(**case))
    session.commit()

    stats_dicts = [
        {"year": s.year, "province": s.province, "denomination": s.denomination,
         "passed": s.passed, "seized": s.seized}
        for s in session.query(CounterfeitStat).all()
    ]
    patterns = aggregate_patterns(stats_dicts)
    court_cases = [{"jurisdiction": c.jurisdiction} for c in session.query(CourtCase).all()]
    correlation = correlate_with_court_cases(patterns, court_cases)

    logger.info(f"Counterfeit stats rows: {len(sources['stats'])}, court cases: {len(sources['court_cases'])}")
    if patterns["anomalies"]:
        for a in patterns["anomalies"]:
            logger.warning(
                f"  Counterfeit activity anomaly: {a['year']} total={a['value']} "
                f"(baseline={a['baseline_mean']}, z={a['z_score']})"
            )
    logger.info(f"  Top provinces by volume: {[p for p, _ in patterns['top_provinces'][:3]]}")
    logger.info(f"  Top denominations by volume: {[d for d, _ in patterns['top_denominations'][:3]]}")
    return patterns, correlation


def run():
    logger.info("Initializing database...")
    init_db()
    session = get_session()

    try:
        run_threat_intel_pipeline(session)
    except Exception as e:
        logger.error(f"Threat-intel pipeline failed: {e}")

    try:
        run_counterfeit_pipeline(session)
    except Exception as e:
        logger.error(f"Counterfeit-currency pipeline failed: {e}")

    session.close()
    logger.success("Done.")


if __name__ == "__main__":
    run()
