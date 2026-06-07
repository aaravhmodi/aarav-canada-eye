"""
IOC extraction using iocextract + spaCy NER.
"""
import re
import iocextract
import spacy
from loguru import logger
from config import cfg

_nlp = None

CA_KEYWORDS = [kw.lower() for kw in cfg["canada_keywords"]]
MAX_TEXT = cfg["collection"]["max_text_length"]

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
MITRE_RE = re.compile(r'T\d{4}(?:\.\d{3})?')


def get_nlp():
    global _nlp
    if _nlp is None:
        logger.info("Loading spaCy model...")
        _nlp = spacy.load("en_core_web_sm")
    return _nlp


def extract_iocs(text: str) -> dict:
    text = text[:MAX_TEXT]
    return {
        "ips":     list(set(iocextract.extract_ips(text, refang=True))),
        "domains": list(set(iocextract.extract_urls(text, refang=True))),
        "hashes":  list(set(iocextract.extract_hashes(text))),
        "emails":  list(set(iocextract.extract_emails(text, refang=True))),
        "cves":    list(set(CVE_RE.findall(text))),
        "ttps":    list(set(MITRE_RE.findall(text))),
    }


def extract_entities(text: str) -> dict:
    nlp = get_nlp()
    doc = nlp(text[:100_000])
    return {
        "orgs":      list(set(e.text for e in doc.ents if e.label_ == "ORG")),
        "locations": list(set(e.text for e in doc.ents if e.label_ in ("GPE", "LOC"))),
        "persons":   list(set(e.text for e in doc.ents if e.label_ == "PERSON")),
    }


def is_canada_relevant(text: str, entities: dict) -> bool:
    combined = (text + str(entities)).lower()
    return any(kw in combined for kw in CA_KEYWORDS)


def process_document(doc: dict) -> dict:
    text = doc.get("raw_text", "")
    iocs = extract_iocs(text)
    entities = extract_entities(text)
    return {
        **doc,
        "iocs": iocs,
        "entities": entities,
        "canada_relevant": is_canada_relevant(text, entities),
    }
