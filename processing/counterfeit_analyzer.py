"""
Pattern/trend analysis over collected counterfeit-currency stats and court cases.
"""
from collections import defaultdict
from statistics import mean, pstdev
from loguru import logger


def aggregate_patterns(stats: list[dict]) -> dict:
    """Roll RCMP CounterfeitStat rows up into year-over-year trends, denomination/province
    breakdowns, and anomaly flags (z-score > 2 on year-over-year seizure change)."""
    by_year = defaultdict(lambda: {"passed": 0, "seized": 0})
    by_province_year = defaultdict(lambda: {"passed": 0, "seized": 0})
    by_denom_year = defaultdict(lambda: {"passed": 0, "seized": 0})

    for row in stats:
        year = row.get("year")
        if year is None:
            continue
        by_year[year]["passed"] += row.get("passed", 0) or 0
        by_year[year]["seized"] += row.get("seized", 0) or 0

        if row.get("province"):
            key = (row["province"], year)
            by_province_year[key]["passed"] += row.get("passed", 0) or 0
            by_province_year[key]["seized"] += row.get("seized", 0) or 0

        if row.get("denomination"):
            key = (row["denomination"], year)
            by_denom_year[key]["passed"] += row.get("passed", 0) or 0
            by_denom_year[key]["seized"] += row.get("seized", 0) or 0

    years_sorted = sorted(by_year)
    yoy_totals = [by_year[y]["seized"] + by_year[y]["passed"] for y in years_sorted]

    anomalies = _flag_anomalies(years_sorted, yoy_totals)

    province_totals = defaultdict(lambda: {"passed": 0, "seized": 0})
    for (province, year), v in by_province_year.items():
        province_totals[province]["passed"] += v["passed"]
        province_totals[province]["seized"] += v["seized"]
    top_provinces = sorted(
        province_totals.items(), key=lambda kv: kv[1]["passed"] + kv[1]["seized"], reverse=True
    )[:5]

    denom_totals = defaultdict(lambda: {"passed": 0, "seized": 0})
    for (denom, year), v in by_denom_year.items():
        denom_totals[denom]["passed"] += v["passed"]
        denom_totals[denom]["seized"] += v["seized"]
    top_denoms = sorted(
        denom_totals.items(), key=lambda kv: kv[1]["passed"] + kv[1]["seized"], reverse=True
    )[:5]

    result = {
        "by_year": dict(by_year),
        "by_province": dict(province_totals),
        "by_denomination": dict(denom_totals),
        "top_provinces": top_provinces,
        "top_denominations": top_denoms,
        "anomalies": anomalies,
    }
    logger.info(
        f"Counterfeit pattern analysis: {len(years_sorted)} years, "
        f"{len(province_totals)} provinces, {len(anomalies)} anomalous years flagged"
    )
    return result


def _flag_anomalies(years: list[int], totals: list[int]) -> list[dict]:
    """Flag years where total counterfeit activity (passed+seized) deviates >2 standard
    deviations from the trailing mean — a simple, explainable spike detector, not a claim of
    causality. Needs at least 3 prior years of history to compute a meaningful baseline."""
    anomalies = []
    for i in range(3, len(years)):
        history = totals[:i]
        mu, sigma = mean(history), pstdev(history) or 1.0
        z = (totals[i] - mu) / sigma
        if abs(z) > 2:
            anomalies.append({
                "year": years[i], "value": totals[i], "baseline_mean": round(mu, 1), "z_score": round(z, 2),
            })
    return anomalies


def correlate_with_court_cases(patterns: dict, court_cases: list[dict]) -> dict:
    """Join court case volume against provincial seizure volume by jurisdiction, for a rough
    'is enforcement activity tracking incident volume' signal."""
    jurisdiction_to_province = {
        "on": "Ontario", "bc": "British Columbia", "ab": "Alberta", "qc": "Quebec",
    }
    cases_by_province = defaultdict(int)
    for case in court_cases:
        province = jurisdiction_to_province.get((case.get("jurisdiction") or "").lower())
        if province:
            cases_by_province[province] += 1

    correlation = []
    for province, totals in patterns.get("by_province", {}).items():
        correlation.append({
            "province": province,
            "incidents": totals["passed"] + totals["seized"],
            "court_cases": cases_by_province.get(province, 0),
        })
    return {"by_province": sorted(correlation, key=lambda r: r["incidents"], reverse=True)}
