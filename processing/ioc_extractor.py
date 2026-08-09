"""
IOC extraction using iocextract + spaCy NER.
"""
import re
from urllib.parse import urlparse
import iocextract
import spacy
from loguru import logger
from config import cfg

_nlp = None

MAX_TEXT = cfg["collection"]["max_text_length"]

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
# ATT&CK technique IDs are Txxxx starting with a literal "1" (T1000-T16xx today), optionally
# with a .xxx sub-technique suffix. Anchored with \b so it doesn't match arbitrary "Txxxx"
# strings (release names, PT-1000 part numbers, etc.) or fall outside the T1### range.
MITRE_RE = re.compile(r'\bT1\d{3}(?:\.\d{3})?\b')


def _build_keyword_patterns(keywords: list[str]) -> list[re.Pattern]:
    """Compile each configured keyword into a word-boundary-safe regex so short tokens like
    "cra" or "bmo" don't match as substrings inside unrelated words ("cracked", "bmoney")."""
    patterns = []
    for kw in keywords:
        kw = kw.lower().strip()
        if kw == ".ca":
            # Match the .ca TLD specifically, not ".ca" appearing mid-word (e.g. "example.cases").
            patterns.append(re.compile(r'\.ca\b'))
        else:
            patterns.append(re.compile(r'\b' + re.escape(kw) + r'\b'))
    return patterns


CA_KEYWORD_PATTERNS = _build_keyword_patterns(cfg["canada_keywords"])


def get_nlp():
    """Load the configured spaCy model, falling back to en_core_web_sm (bundled via
    requirements.txt) if the configured model (e.g. the much larger en_core_web_trf) isn't
    installed, instead of crashing the whole pipeline on the first document."""
    global _nlp
    if _nlp is not None:
        return _nlp

    preferred = cfg["nlp"]["spacy_model"]
    candidates = [preferred] + [m for m in ("en_core_web_sm", "en_core_web_trf") if m != preferred]

    for name in candidates:
        try:
            logger.info(f"Loading spaCy model '{name}'...")
            _nlp = spacy.load(name)
            if name != preferred:
                logger.warning(
                    f"Configured spaCy model '{preferred}' isn't installed — falling back to "
                    f"'{name}'. Run `python -m spacy download {preferred}` for full accuracy."
                )
            return _nlp
        except OSError:
            continue

    raise RuntimeError(
        "No spaCy model is installed. Run: python -m spacy download en_core_web_sm"
    )


def extract_iocs(text: str) -> dict:
    text = text[:MAX_TEXT]
    urls = list(set(iocextract.extract_urls(text, refang=True)))
    return {
        "ips":     list(set(iocextract.extract_ips(text, refang=True))),
        "urls":    urls,
        "domains": _urls_to_domains(urls),
        "hashes":  list(set(iocextract.extract_hashes(text))),
        "emails":  list(set(iocextract.extract_emails(text, refang=True))),
        "cves":    list(set(CVE_RE.findall(text))),
        "ttps":    list(set(MITRE_RE.findall(text))),
    }


def _urls_to_domains(urls: list[str]) -> list[str]:
    """iocextract only extracts full URLs, not bare domains — MISP's "domain" attribute type
    (and clustering fingerprints) need the hostname, not scheme+path."""
    domains = set()
    for url in urls:
        host = urlparse(url).netloc or url
        host = host.split("@")[-1].split(":")[0]  # strip userinfo and port
        if host:
            domains.add(host.lower())
    return list(domains)


def extract_entities(text: str) -> dict:
    nlp = get_nlp()
    doc = nlp(text[:100_000])
    return {
        "orgs":      list(set(e.text for e in doc.ents if e.label_ == "ORG")),
        "locations": list(set(e.text for e in doc.ents if e.label_ in ("GPE", "LOC"))),
        "persons":   list(set(e.text for e in doc.ents if e.label_ == "PERSON")),
    }


def is_canada_relevant(text: str, entities: dict) -> bool:
    combined = (text + " " + str(entities)).lower()
    return any(p.search(combined) for p in CA_KEYWORD_PATTERNS)


def process_document(doc: dict) -> dict:
    text = doc.get("raw_text", "")
    try:
        iocs = extract_iocs(text)
        entities = extract_entities(text)
        canada_relevant = is_canada_relevant(text, entities)
    except Exception as e:
        # A single malformed document (encoding issue, spaCy edge case, etc.) shouldn't take
        # down a whole collection run.
        logger.warning(f"Failed to process document {doc.get('source_url')}: {e}")
        iocs = {"ips": [], "urls": [], "domains": [], "hashes": [], "emails": [], "cves": [], "ttps": []}
        entities = {"orgs": [], "locations": [], "persons": []}
        canada_relevant = False
    return {
        **doc,
        "iocs": iocs,
        "entities": entities,
        "canada_relevant": canada_relevant,
    }
