"""
Entry point for one-shot collection + processing run (no Celery required).
Usage: python main.py
"""
import asyncio
from loguru import logger
from storage.models import init_db, get_session, RawDocument
from collectors.rss_collector import collect_rss_feeds
from collectors.paste_collector import collect_all_pastes
from collectors.ca_specific import collect_all_ca_sources
from processing.ioc_extractor import process_document
from processing.clusterer import cluster_documents
from integrations.misp_client import push_actor_profile


def save_doc(session, doc: dict, processed: dict):
    row = RawDocument(
        source_url=doc["source_url"],
        source_type=doc["source_type"],
        raw_text=doc["raw_text"][:50000],
        canada_relevant=processed["canada_relevant"],
    )
    session.add(row)


def run():
    logger.info("Initializing database...")
    init_db()
    session = get_session()

    logger.info("Collecting sources...")
    rss_docs = collect_rss_feeds()
    ca_docs = collect_all_ca_sources()
    paste_docs = asyncio.run(collect_all_pastes())

    all_docs = rss_docs + ca_docs + paste_docs
    logger.info(f"Collected {len(all_docs)} total documents")

    processed = []
    for doc in all_docs:
        p = process_document(doc)
        save_doc(session, doc, p)
        if p["canada_relevant"]:
            processed.append(p)

    session.commit()
    logger.info(f"CA-relevant: {len(processed)} documents")

    profiles = cluster_documents(processed)
    logger.info(f"Built {len(profiles)} actor profiles")

    for profile in profiles:
        logger.info(f"  Actor: {profile['actor_label']} — {profile['incident_count']} incidents, "
                    f"{len(profile['ips'])} IPs, {len(profile['domains'])} domains")
        push_actor_profile(profile)

    session.close()
    logger.success("Done.")


if __name__ == "__main__":
    run()
