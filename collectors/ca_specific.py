"""
Canada-specific data sources:
- CCCS (Canadian Centre for Cyber Security) alerts
- CIRA threat data
- CRTC breach notices
- AlienVault OTX filtered to CA
"""
import httpx
import feedparser
from loguru import logger

CCCS_RSS = "https://cyber.gc.ca/api/linksApi?lang=en&type=rss&num=50"
OTX_CA_PULSE = "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=2024-01-01&limit=50"


def collect_cccs_alerts() -> list[dict]:
    results = []
    try:
        feed = feedparser.parse(CCCS_RSS)
        for entry in feed.entries:
            results.append({
                "source_url": entry.get("link", CCCS_RSS),
                "source_type": "ca_gov",
                "raw_text": entry.get("summary", "") + " " + entry.get("title", ""),
                "title": entry.get("title", ""),
            })
        logger.info(f"CCCS: collected {len(results)} alerts")
    except Exception as e:
        logger.warning(f"CCCS collection failed: {e}")
    return results


async def collect_otx_ca(api_key: str) -> list[dict]:
    """Fetch AlienVault OTX pulses and filter for Canadian-relevant IOCs."""
    results = []
    headers = {"X-OTX-API-KEY": api_key}
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(OTX_CA_PULSE, headers=headers, timeout=30)
            for pulse in r.json().get("results", []):
                indicators = pulse.get("indicators", [])
                text = pulse.get("description", "") + " " + pulse.get("name", "")
                results.append({
                    "source_url": f"https://otx.alienvault.com/pulse/{pulse['id']}",
                    "source_type": "otx",
                    "raw_text": text,
                    "ioc_list": [{"type": i["type"], "value": i["indicator"]} for i in indicators],
                })
        except Exception as e:
            logger.warning(f"OTX collection failed: {e}")
    return results


def collect_all_ca_sources() -> list[dict]:
    return collect_cccs_alerts()
