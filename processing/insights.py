"""
Turns raw query results / pattern-analysis output into short, specific, natural-language
insights with a severity level — the "so what, do this next" layer on top of the tables and
charts the dashboard already shows.
"""
from datetime import datetime, timedelta

RECENT_WINDOW_DAYS = 7
HIGH_ABUSE_SCORE = 50


def threat_actor_insights(actors: list, iocs: list) -> list[dict]:
    """actors: list[storage.models.ActorProfile], iocs: list[storage.models.IOC]."""
    insights = []
    if not actors:
        return [{"severity": "info", "text": "No actor profiles yet — insights will appear once clustering has run against collected data."}]

    top = max(actors, key=lambda a: a.incident_count)
    insights.append({
        "severity": "high",
        "text": (
            f"{top.actor_label} has the most corroborated incidents ({top.incident_count}) "
            f"— prioritize this one for manual review first."
        ),
    })

    since = datetime.utcnow() - timedelta(days=RECENT_WINDOW_DAYS)
    recent = [a for a in actors if a.last_seen and a.last_seen >= since]
    if recent:
        labels = ", ".join(a.actor_label for a in recent[:5])
        more = f" (+{len(recent) - 5} more)" if len(recent) > 5 else ""
        insights.append({
            "severity": "high",
            "text": f"{len(recent)} actor(s) active in the last {RECENT_WINDOW_DAYS} days: {labels}{more} — treat as current, not historical.",
        })

    high_risk_ips = [
        ioc for ioc in iocs
        if ioc.ioc_type == "ip" and isinstance(ioc.enrichment, dict)
        and (ioc.enrichment.get("abuse_score") or 0) >= HIGH_ABUSE_SCORE
    ]
    if high_risk_ips:
        sample = ", ".join(sorted({ioc.value for ioc in high_risk_ips})[:5])
        insights.append({
            "severity": "high",
            "text": f"{len(high_risk_ips)} IP(s) flagged with AbuseIPDB confidence ≥{HIGH_ABUSE_SCORE}: {sample} — recommend blocking/monitoring at the perimeter.",
        })

    unpushed = [a for a in actors if not a.misp_event_uuid]
    if unpushed:
        insights.append({
            "severity": "medium",
            "text": f"{len(unpushed)} of {len(actors)} actor profiles haven't been pushed to MISP — check MISP connectivity or re-run the clustering task.",
        })

    thin = [a for a in actors if not (a.ips or a.domains)]
    if len(thin) / len(actors) > 0.5:
        insights.append({
            "severity": "info",
            "text": (
                f"{len(thin)} of {len(actors)} profiles have no network indicators (IPs/domains) — "
                f"clustering is currently loosened (eps=0.45, min_samples=1) to surface profiles from low "
                f"volume. Tighten it back in config/settings.yaml once collection volume is high enough "
                f"that precision matters more than recall."
            ),
        })

    return insights


def counterfeit_insights(patterns: dict, correlation: dict) -> list[dict]:
    insights = []
    if not patterns.get("by_year"):
        return [{"severity": "info", "text": "No counterfeit stats collected yet — run the collector to generate insights."}]

    for anomaly in patterns["anomalies"]:
        insights.append({
            "severity": "high",
            "text": (
                f"{anomaly['year']} activity ({anomaly['value']:,}) is {anomaly['z_score']} standard "
                f"deviations above the trailing baseline ({anomaly['baseline_mean']:,.0f}) — worth "
                f"checking for a new counterfeiting ring or a change in detection/reporting practices."
            ),
        })

    top_provinces = patterns.get("top_provinces", [])
    if top_provinces:
        province, totals = top_provinces[0]
        national_total = sum(v["passed"] + v["seized"] for v in patterns["by_province"].values()) or 1
        share = (totals["passed"] + totals["seized"]) / national_total * 100
        insights.append({
            "severity": "medium",
            "text": f"{province} accounts for {share:.0f}% of all recorded passed+seized volume — the highest of any province/territory. Prioritize enforcement resources there.",
        })

    top_denoms = patterns.get("top_denominations", [])
    if top_denoms:
        denom, totals = top_denoms[0]
        national_total = sum(v["passed"] + v["seized"] for v in patterns["by_denomination"].values()) or 1
        share = (totals["passed"] + totals["seized"]) / national_total * 100
        insights.append({
            "severity": "medium",
            "text": f"{denom} notes make up {share:.0f}% of counterfeit volume by denomination — retailers and banks should prioritize {denom} authentication checks over other denominations.",
        })

    gaps = [
        row for row in correlation.get("by_province", [])
        if row["incidents"] > 0 and row["court_cases"] == 0
    ]
    if gaps:
        top_gap = gaps[0]
        note = "" if any(row["court_cases"] > 0 for row in correlation.get("by_province", [])) else " (note: no CanLII data collected yet — set CANLII_API_KEY to make this comparison meaningful)"
        insights.append({
            "severity": "info",
            "text": f"{top_gap['province']} has {top_gap['incidents']:,} recorded incidents but 0 tracked court cases{note}.",
        })

    return insights
