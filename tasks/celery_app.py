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
}


@app.task(name="tasks.celery_app.task_collect_rss")
def task_collect_rss():
    from collectors.rss_collector import collect_rss_feeds
    from processing.ioc_extractor import process_document
    from storage.models import get_session, RawDocument

    docs = collect_rss_feeds()
    session = get_session()
    saved = 0
    for doc in docs:
        processed = process_document(doc)
        if processed["canada_relevant"]:
            row = RawDocument(
                source_url=doc["source_url"],
                source_type=doc["source_type"],
                raw_text=doc["raw_text"],
                canada_relevant=True,
            )
            session.add(row)
            saved += 1
    session.commit()
    logger.info(f"RSS: saved {saved} CA-relevant documents")


@app.task(name="tasks.celery_app.task_collect_pastes")
def task_collect_pastes():
    from collectors.paste_collector import collect_all_pastes
    from processing.ioc_extractor import process_document
    from storage.models import get_session, RawDocument

    docs = asyncio.run(collect_all_pastes())
    session = get_session()
    saved = 0
    for doc in docs:
        processed = process_document(doc)
        if processed["canada_relevant"]:
            row = RawDocument(
                source_url=doc["source_url"],
                source_type=doc["source_type"],
                raw_text=doc["raw_text"],
                canada_relevant=True,
            )
            session.add(row)
            saved += 1
    session.commit()
    logger.info(f"Pastes: saved {saved} CA-relevant documents")


@app.task(name="tasks.celery_app.task_collect_ca")
def task_collect_ca():
    from collectors.ca_specific import collect_all_ca_sources
    from processing.ioc_extractor import process_document
    from storage.models import get_session, RawDocument

    docs = collect_all_ca_sources()
    session = get_session()
    for doc in docs:
        processed = process_document(doc)
        row = RawDocument(
            source_url=doc["source_url"],
            source_type=doc["source_type"],
            raw_text=doc["raw_text"],
            canada_relevant=True,  # CCCS is always CA-relevant
        )
        session.add(row)
    session.commit()


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
            uuid = push_actor_profile(profile)
            if uuid:
                actor.misp_event_uuid = uuid

    for r in unprocessed:
        r.processed = True

    session.commit()
    logger.info(f"Clustering: built {len(profiles)} actor profiles")
