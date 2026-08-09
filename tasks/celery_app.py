"""
Celery task definitions and periodic schedule.
"""
import asyncio
from celery import Celery
from celery.schedules import crontab
from loguru import logger
from config import cfg

app = Celery("osint_ca", broker=cfg["storage"]["redis_url"], backend=cfg["storage"]["redis_url"])

app.conf.beat_schedule = {
    "collect-rss-hourly": {
        "task": "tasks.celery_app.task_collect_rss",
        "schedule": crontab(minute=0),
    },
    "collect-pastes-every-30min": {
        "task": "tasks.celery_app.task_collect_pastes",
        "schedule": crontab(minute="*/30"),
    },
    "collect-ca-sources-hourly": {
        "task": "tasks.celery_app.task_collect_ca",
        "schedule": crontab(minute=5),
    },
    "run-clustering-every-6h": {
        "task": "tasks.celery_app.task_cluster_and_push",
        "schedule": crontab(minute=0, hour="*/6"),
    },
    "collect-counterfeit-sources-daily": {
        "task": "tasks.celery_app.task_collect_counterfeit",
        "schedule": crontab(minute=15, hour=6),
    },
}


def _save_processed_docs(session, docs, force_canada_relevant=False):
    """Shared by the RSS/paste/CA collector tasks below: process each doc, persist the
    RawDocument row plus its extracted IOCs (previously this only ever happened for
    CA-relevant docs and the IOC table was never written to at all)."""
    from processing.ioc_extractor import process_document
    from storage.models import RawDocument, save_iocs

    saved = 0
    for doc in docs:
        processed = process_document(doc)
        canada_relevant = True if force_canada_relevant else processed["canada_relevant"]
        if not canada_relevant:
            continue
        row = RawDocument(
            source_url=doc["source_url"],
            source_type=doc["source_type"],
            # Postgres text columns reject NUL bytes outright; some feed/paste content has them.
            raw_text=doc["raw_text"].replace("\x00", "")[:50000],
            canada_relevant=True,
        )
        session.add(row)
        session.flush()
        save_iocs(session, row, processed["iocs"])
        saved += 1
    session.commit()
    return saved


@app.task(name="tasks.celery_app.task_collect_rss")
def task_collect_rss():
    from collectors.rss_collector import collect_rss_feeds
    from storage.models import get_session

    docs = collect_rss_feeds()
    session = get_session()
    saved = _save_processed_docs(session, docs)
    session.close()
    logger.info(f"RSS: saved {saved} CA-relevant documents")


@app.task(name="tasks.celery_app.task_collect_pastes")
def task_collect_pastes():
    from collectors.paste_collector import collect_all_pastes
    from storage.models import get_session

    docs = asyncio.run(collect_all_pastes())
    session = get_session()
    saved = _save_processed_docs(session, docs)
    session.close()
    logger.info(f"Pastes: saved {saved} CA-relevant documents")


@app.task(name="tasks.celery_app.task_collect_ca")
def task_collect_ca():
    from collectors.ca_specific import collect_all_ca_sources
    from storage.models import get_session

    docs = collect_all_ca_sources()
    session = get_session()
    saved = _save_processed_docs(session, docs, force_canada_relevant=True)  # CCCS is always CA-relevant
    session.close()
    logger.info(f"CA sources: saved {saved} documents")


@app.task(name="tasks.celery_app.task_cluster_and_push")
def task_cluster_and_push():
    from processing.clusterer import cluster_documents
    from processing.ioc_extractor import process_document
    from integrations.misp_client import push_actor_profile
    from storage.models import get_session, RawDocument, ActorProfile

    session = get_session()
    unprocessed = (
        session.query(RawDocument)
        .filter_by(canada_relevant=True, processed=False)
        .limit(500)
        .all()
    )

    docs = [
        {"source_url": r.source_url, "source_type": r.source_type,
         "raw_text": r.raw_text, "collected_at": r.collected_at}
        for r in unprocessed
    ]

    processed = [process_document(d) for d in docs]
    profiles = cluster_documents(processed)

    for profile in profiles:
        existing = session.query(ActorProfile).filter_by(actor_label=profile["actor_label"]).first()
        if not existing:
            actor = ActorProfile(**{k: v for k, v in profile.items() if k != "source_docs"})
            session.add(actor)
            try:
                uuid = push_actor_profile(profile)
                if uuid:
                    actor.misp_event_uuid = uuid
            except Exception as e:
                # A misconfigured/unreachable MISP shouldn't lose the actor profile itself —
                # it's still saved locally, just without a misp_event_uuid.
                logger.warning(f"MISP push failed for {profile['actor_label']}: {e}")

    for r in unprocessed:
        r.processed = True

    session.commit()
    session.close()
    logger.info(f"Clustering: built {len(profiles)} actor profiles")


@app.task(name="tasks.celery_app.task_collect_counterfeit")
def task_collect_counterfeit():
    """Daily pull of RCMP counterfeit stats + CanLII court cases, then trend analysis.
    See collectors/counterfeit_sources.py and processing/counterfeit_analyzer.py."""
    from collectors.counterfeit_sources import collect_all_counterfeit_sources
    from processing.counterfeit_analyzer import aggregate_patterns
    from processing.ioc_extractor import process_document
    from storage.models import get_session, CounterfeitStat, CourtCase, RawDocument

    session = get_session()
    sources = collect_all_counterfeit_sources()

    for row in sources["stats"]:
        session.add(CounterfeitStat(**row))
    for doc in sources["context_docs"]:
        processed = process_document(doc)
        session.add(RawDocument(
            source_url=doc["source_url"], source_type=doc["source_type"],
            raw_text=doc["raw_text"].replace("\x00", "")[:50000],
            canada_relevant=processed["canada_relevant"],
        ))
    for case in sources["court_cases"]:
        if not session.query(CourtCase).filter_by(canlii_id=case["canlii_id"]).first():
            session.add(CourtCase(**case))
    session.commit()

    stats_dicts = [
        {"year": s.year, "province": s.province, "denomination": s.denomination,
         "passed": s.passed, "seized": s.seized}
        for s in session.query(CounterfeitStat).all()
    ]
    patterns = aggregate_patterns(stats_dicts)
    session.close()
    logger.info(
        f"Counterfeit: {len(sources['stats'])} stat rows, {len(sources['court_cases'])} court "
        f"cases, {len(patterns['anomalies'])} anomalous years"
    )
