"""
Tor-based collector. Requires Tor daemon running locally.
"""
import time
import stem.process
from stem import Signal
from stem.control import Controller
import requests
from loguru import logger
from config import cfg

SOCKS_PORT = cfg["tor"]["socks_port"]
CONTROL_PORT = cfg["tor"]["control_port"]
CONTROL_PASSWORD = cfg["tor"]["control_password"]

# Known publicly-indexed paste mirrors and cleared forums (not private/illegal markets)
ONION_TARGETS = [
    # Add .onion URLs of publicly indexed security paste mirrors here
    # Example: known Tor paste services used by researchers
]


def get_tor_session() -> requests.Session:
    session = requests.Session()
    session.proxies = {
        "http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
        "https": f"socks5h://127.0.0.1:{SOCKS_PORT}",
    }
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; OSINTResearch/1.0)"
    return session


def rotate_identity():
    try:
        with Controller.from_port(port=CONTROL_PORT) as ctrl:
            ctrl.authenticate(password=CONTROL_PASSWORD or None)
            ctrl.signal(Signal.NEWNYM)
            time.sleep(ctrl.get_newnym_wait())
            logger.info("Tor identity rotated")
    except Exception as e:
        logger.warning(f"Failed to rotate Tor identity: {e}")


def scrape_url(url: str, session: requests.Session) -> str | None:
    try:
        r = session.get(url, timeout=cfg["collection"]["request_timeout"])
        r.raise_for_status()
        logger.info(f"Scraped {url} ({len(r.text)} chars)")
        return r.text
    except Exception as e:
        logger.warning(f"Failed to scrape {url}: {e}")
        return None


def collect_tor_sources() -> list[dict]:
    session = get_tor_session()
    results = []
    for url in ONION_TARGETS:
        text = scrape_url(url, session)
        if text:
            results.append({"source_url": url, "source_type": "tor", "raw_text": text})
        rotate_identity()
    return results
