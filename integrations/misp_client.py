"""
MISP integration — push actor profiles as events.
"""
from pymisp import PyMISP, MISPEvent, MISPAttribute
from loguru import logger
from config import cfg


def get_misp() -> PyMISP | None:
    url = cfg["misp"]["url"]
    key = cfg["misp"]["key"]
    if not url or not key:
        logger.warning("MISP not configured — skipping push")
        return None
    return PyMISP(url, key, ssl=cfg["misp"]["verify_ssl"])


def push_actor_profile(profile: dict) -> str | None:
    misp = get_misp()
    if not misp:
        return None

    event = MISPEvent()
    event.info = f"CA Threat Actor: {profile['actor_label']}"
    event.distribution = cfg["misp"]["default_distribution"]
    event.threat_level_id = cfg["misp"]["default_threat_level"]

    for tag in cfg["misp"]["tags"]:
        event.add_tag(tag)

    for ip in profile.get("ips", []):
        event.add_attribute("ip-dst", ip, comment="Canada OSINT")
    for domain in profile.get("domains", []):
        event.add_attribute("domain", domain)
    for h in profile.get("hashes", []):
        attr_type = "md5" if len(h) == 32 else "sha256" if len(h) == 64 else "sha1"
        event.add_attribute(attr_type, h)
    for ttp in profile.get("ttps", []):
        event.add_attribute("text", ttp, comment="MITRE ATT&CK TTP")

    result = misp.add_event(event)
    uuid = result.get("Event", {}).get("uuid")
    logger.info(f"Pushed actor {profile['actor_label']} to MISP — UUID: {uuid}")
    return uuid


def pull_ca_events() -> list[dict]:
    misp = get_misp()
    if not misp:
        return []
    events = misp.search(tags=["osint:canada"], pythonify=True)
    return [e.to_dict() for e in events]
