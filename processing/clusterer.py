"""
Actor profile clustering using sentence embeddings + DBSCAN.
"""
import hashlib
from datetime import datetime
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import normalize
from loguru import logger
from config import cfg

_model = None


def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        logger.info("Loading sentence-transformers model...")
        _model = SentenceTransformer(cfg["clustering"]["model"])
    return _model


def _ioc_fingerprint(doc: dict) -> str:
    iocs = doc.get("iocs", {})
    parts = (
        iocs.get("ips", [])
        + iocs.get("domains", [])
        + iocs.get("hashes", [])
    )
    return " ".join(sorted(parts))


def cluster_documents(docs: list[dict]) -> list[dict]:
    # Was hardcoded to `< 2`, which silently discarded everything on any run with just one
    # CA-relevant document, regardless of how low dbscan_min_samples was configured. Now it
    # only requires as many docs as the configured min_samples actually needs.
    if len(docs) < cfg["clustering"]["dbscan_min_samples"]:
        return []

    texts = [_ioc_fingerprint(d) + " " + d.get("raw_text", "")[:500] for d in docs]
    model = get_model()
    embeddings = normalize(model.encode(texts, show_progress_bar=False))

    labels = DBSCAN(
        eps=cfg["clustering"]["dbscan_eps"],
        min_samples=cfg["clustering"]["dbscan_min_samples"],
        metric="cosine",
    ).fit_predict(embeddings)

    clusters: dict[int, list[dict]] = {}
    for idx, label in enumerate(labels):
        if label == -1:
            continue
        clusters.setdefault(label, []).append(docs[idx])

    logger.info(f"Clustering: {len(docs)} docs → {len(clusters)} actor clusters")
    return [_merge_cluster(c) for c in clusters.values()]


def _merge_cluster(docs: list[dict]) -> dict:
    ips, domains, hashes, orgs, ttps = set(), set(), set(), set(), set()
    timestamps = []

    for d in docs:
        iocs = d.get("iocs", {})
        ips.update(iocs.get("ips", []))
        domains.update(iocs.get("domains", []))
        hashes.update(iocs.get("hashes", []))
        ttps.update(iocs.get("ttps", []))
        ents = d.get("entities", {})
        orgs.update(ents.get("orgs", []))
        if "collected_at" in d:
            timestamps.append(d["collected_at"])

    # Bug: hashing only ips|domains meant every cluster with neither (common now that
    # dbscan_min_samples=1 lets single, IOC-less documents form their own "actor") hashed the
    # same empty string -> identical label "CA-ACTOR-DA39A3EE5E6B" (sha1('') truncated) for
    # every one of them. task_cluster_and_push dedupes by actor_label, so all but the first
    # such cluster were silently dropped as "already exists" and never saved. Folding in
    # hashes/ttps/orgs, and finally the cluster's source URLs as a last-resort tiebreaker,
    # means two genuinely different clusters can no longer collide onto one label.
    source_docs = sorted(d.get("source_url", "") for d in docs)
    fingerprint = "|".join(sorted(ips | domains | hashes | ttps | orgs) or source_docs)
    uid = hashlib.sha1(fingerprint.encode()).hexdigest()[:12]

    return {
        "actor_label": f"CA-ACTOR-{uid.upper()}",
        "ips": list(ips),
        "domains": list(domains),
        "hashes": list(hashes),
        "ttps": list(ttps),
        "orgs_targeted": list(orgs),
        "incident_count": len(docs),
        "first_seen": min(timestamps) if timestamps else datetime.utcnow(),
        "last_seen": max(timestamps) if timestamps else datetime.utcnow(),
        "source_docs": [d.get("source_url") for d in docs],
    }
