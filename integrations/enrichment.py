"""
IOC enrichment: Shodan, AbuseIPDB, VirusTotal.
"""
import httpx
import shodan as shodan_lib
from loguru import logger
from config import cfg


def enrich_ip(ip: str) -> dict:
    result = {"ip": ip}
    result.update(_shodan_lookup(ip))
    result.update(_abuseipdb_lookup(ip))
    return result


def _shodan_lookup(ip: str) -> dict:
    key = cfg["enrichment"]["shodan_key"]
    if not key:
        return {}
    try:
        api = shodan_lib.Shodan(key)
        host = api.host(ip)
        return {
            "country": host.get("country_code"),
            "org": host.get("org"),
            "asn": host.get("asn"),
            "is_canadian": host.get("country_code") == "CA",
            "open_ports": host.get("ports", []),
            "hostnames": host.get("hostnames", []),
            "tags": host.get("tags", []),
        }
    except shodan_lib.APIError as e:
        logger.debug(f"Shodan lookup failed for {ip}: {e}")
        return {}


def _abuseipdb_lookup(ip: str) -> dict:
    key = cfg["enrichment"]["abuseipdb_key"]
    if not key:
        return {}
    try:
        r = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        data = r.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "abuse_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
            "abuse_domain": data.get("domain"),
        }
    except Exception as e:
        logger.debug(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {}


def enrich_hash(hash_value: str) -> dict:
    key = cfg["enrichment"]["vt_key"]
    if not key:
        return {}
    try:
        r = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers={"x-apikey": key},
            timeout=15,
        )
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless": stats.get("harmless", 0),
        }
    except Exception as e:
        logger.debug(f"VT lookup failed for {hash_value}: {e}")
        return {}
