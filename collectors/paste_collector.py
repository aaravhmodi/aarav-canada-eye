"""
Clearnet paste site collector.
"""
import httpx
from bs4 import BeautifulSoup
from loguru import logger
from config import cfg

PASTE_SITES = cfg["paste_sites"]
TIMEOUT = cfg["collection"]["request_timeout"]


async def fetch_pastebin_recent(client: httpx.AsyncClient) -> list[dict]:
    results = []
    try:
        r = await client.get("https://pastebin.com/archive", timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        links = [a["href"] for a in soup.select("table.maintable a") if a.get("href", "").startswith("/")]
        for path in links[:30]:
            raw_url = f"https://pastebin.com/raw{path}"
            paste = await client.get(raw_url, timeout=TIMEOUT)
            results.append({
                "source_url": raw_url,
                "source_type": "paste",
                "raw_text": paste.text,
            })
    except Exception as e:
        logger.warning(f"Pastebin collection failed: {e}")
    return results


async def fetch_paste_ee_recent(client: httpx.AsyncClient) -> list[dict]:
    results = []
    try:
        r = await client.get("https://paste.ee/recent", timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        links = [a["href"] for a in soup.select("a.paste-link") if a.get("href")]
        for link in links[:20]:
            raw_url = link.replace("/p/", "/r/")
            paste = await client.get(raw_url, timeout=TIMEOUT)
            results.append({
                "source_url": raw_url,
                "source_type": "paste",
                "raw_text": paste.text,
            })
    except Exception as e:
        logger.warning(f"paste.ee collection failed: {e}")
    return results


async def collect_all_pastes() -> list[dict]:
    async with httpx.AsyncClient(follow_redirects=True) as client:
        pastebin = await fetch_pastebin_recent(client)
        paste_ee = await fetch_paste_ee_recent(client)
    return pastebin + paste_ee
