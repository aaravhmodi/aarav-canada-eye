"""
Streamlit dashboard for CA Threat Actor Profiler + Counterfeit Currency Pattern Tracking.
Run: streamlit run dashboard/app.py
"""
import sys
sys.path.insert(0, ".")

import tempfile
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
from storage.models import get_session, ActorProfile, IOC, RawDocument, CounterfeitStat, CourtCase
from processing.counterfeit_analyzer import aggregate_patterns

st.set_page_config(page_title="CA OSINT Platform", layout="wide")
st.title("Canada OSINT Platform")
st.caption("Threat-actor profiling + counterfeit-currency pattern tracking")

session = get_session()

tab_threat, tab_counterfeit = st.tabs(["🛡️ Threat Actors", "💵 Counterfeit Currency"])

# ══════════════════════════════════════════════════════════════════════════════
# Threat Actor tab
# ══════════════════════════════════════════════════════════════════════════════
with tab_threat:
    with st.sidebar:
        st.header("Threat Actor Filters")
        days_back = st.slider("Days back", 1, 90, 30)
        min_incidents = st.number_input("Min incidents per actor", 1, 50, 2)
        since = datetime.utcnow() - timedelta(days=days_back)

    actors = session.query(ActorProfile).filter(ActorProfile.last_seen >= since).all()
    total_docs = session.query(RawDocument).filter(RawDocument.canada_relevant == True).count()
    total_iocs = session.query(IOC).count()

    col1, col2, col3 = st.columns(3)
    col1.metric("Actor Profiles", len(actors))
    col2.metric("CA-Relevant Documents", total_docs)
    col3.metric("Unique IOCs", total_iocs)

    st.divider()
    st.subheader("Actor Profiles")

    filtered = [a for a in actors if a.incident_count >= min_incidents]

    if filtered:
        df = pd.DataFrame([{
            "Actor": a.actor_label,
            "IPs": len(a.ips or []),
            "Domains": len(a.domains or []),
            "Hashes": len(a.hashes or []),
            "TTPs": len(a.ttps or []),
            "Incidents": a.incident_count,
            "First Seen": a.first_seen,
            "Last Seen": a.last_seen,
            "MISP": "✓" if a.misp_event_uuid else "—",
        } for a in filtered])
        st.dataframe(df, use_container_width=True)

        selected = st.selectbox("Inspect actor", [a.actor_label for a in filtered])
        actor = next(a for a in filtered if a.actor_label == selected)

        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.write("**IPs**")
            st.dataframe(pd.DataFrame({"IP": actor.ips or []}), use_container_width=True)
        with col_b:
            st.write("**Domains**")
            st.dataframe(pd.DataFrame({"Domain": actor.domains or []}), use_container_width=True)
        with col_c:
            st.write("**TTPs (MITRE)**")
            st.dataframe(pd.DataFrame({"TTP": actor.ttps or []}), use_container_width=True)

        if actor.misp_event_uuid:
            misp_url = f"{__import__('config').cfg['misp']['url']}/events/view/{actor.misp_event_uuid}"
            st.markdown(f"[Open in MISP]({misp_url})")
    else:
        st.info("No actor profiles match the current filters.")

    st.divider()
    st.subheader("Collection Sources")
    source_counts = (
        session.query(RawDocument.source_type)
        .filter(RawDocument.canada_relevant == True)
        .all()
    )
    if source_counts:
        src_df = pd.DataFrame(source_counts, columns=["source_type"])
        fig = px.pie(src_df, names="source_type", title="CA-Relevant Docs by Source")
        st.plotly_chart(fig, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════════════
# Counterfeit Currency tab
# ══════════════════════════════════════════════════════════════════════════════
with tab_counterfeit:
    st.info(
        "Stats below are scraped live from the RCMP's published counterfeit-currency tables "
        "(real government data). The banknote image scanner further down uses a model trained "
        "**only on synthetic demo images** — no public dataset of genuine/counterfeit Canadian "
        "notes exists, so treat its output as a pipeline demo, not a real fraud signal. "
        "See processing/banknote_cnn.py for details.",
        icon="ℹ️",
    )

    stats_rows = session.query(CounterfeitStat).all()
    if not stats_rows:
        st.warning(
            "No counterfeit stats collected yet. Run `python main.py` or the "
            "`task_collect_counterfeit` Celery task first."
        )
    else:
        stats_dicts = [{
            "year": s.year, "province": s.province, "denomination": s.denomination,
            "passed": s.passed, "seized": s.seized,
        } for s in stats_rows]
        patterns = aggregate_patterns(stats_dicts)

        years = sorted(patterns["by_year"])
        latest_year = years[-1]
        latest = patterns["by_year"][latest_year]
        prev = patterns["by_year"].get(latest_year - 1, {"passed": 0, "seized": 0})
        yoy_pct = (
            ((latest["passed"] + latest["seized"]) - (prev["passed"] + prev["seized"]))
            / max(prev["passed"] + prev["seized"], 1) * 100
        )

        c1, c2, c3, c4 = st.columns(4)
        c1.metric(f"{latest_year} Passed", f"{latest['passed']:,}")
        c2.metric(f"{latest_year} Seized", f"{latest['seized']:,}")
        c3.metric("YoY Change", f"{yoy_pct:+.0f}%")
        c4.metric("Court Cases Tracked", session.query(CourtCase).count())

        if patterns["anomalies"]:
            for a in patterns["anomalies"]:
                st.warning(
                    f"⚠ Anomalous spike in {a['year']}: total activity {a['value']:,} vs. "
                    f"baseline mean {a['baseline_mean']:,.0f} (z-score {a['z_score']})"
                )

        st.divider()
        st.subheader("National trend — passed vs. seized")
        trend_df = pd.DataFrame([
            {"Year": y, "Passed into circulation": v["passed"], "Seized by law enforcement": v["seized"]}
            for y, v in sorted(patterns["by_year"].items())
        ])
        fig = px.bar(trend_df, x="Year", y=["Passed into circulation", "Seized by law enforcement"], barmode="group")
        st.plotly_chart(fig, use_container_width=True)

        col_p, col_d = st.columns(2)
        with col_p:
            st.subheader("By province")
            prov_df = pd.DataFrame([
                {"Province": p, "Passed": v["passed"], "Seized": v["seized"]}
                for p, v in patterns["by_province"].items()
            ]).sort_values("Seized", ascending=False)
            st.dataframe(prov_df, use_container_width=True)
        with col_d:
            st.subheader("By denomination")
            denom_df = pd.DataFrame([
                {"Denomination": d, "Passed": v["passed"], "Seized": v["seized"]}
                for d, v in patterns["by_denomination"].items()
            ]).sort_values("Seized", ascending=False)
            st.dataframe(denom_df, use_container_width=True)

        st.divider()
        st.subheader("Court cases (CanLII)")
        cases = session.query(CourtCase).all()
        if cases:
            st.dataframe(pd.DataFrame([{
                "Case": c.case_name, "Jurisdiction": c.jurisdiction, "Date": c.decision_date, "URL": c.url,
            } for c in cases]), use_container_width=True)
        else:
            st.caption(
                "No court cases collected — requires a free CanLII API key "
                "(set CANLII_API_KEY in .env). See collectors/counterfeit_sources.py."
            )

    st.divider()
    st.subheader("Banknote security-feature scanner (demo)")
    uploaded = st.file_uploader("Upload a note image (or use a synthetic sample below)", type=["png", "jpg", "jpeg"])
    if st.button("Generate + scan a synthetic sample instead"):
        from processing.banknote_cnn import generate_synthetic_demo_dataset, load_model, analyze_banknote
        import glob, os
        data_dir = generate_synthetic_demo_dataset(n_samples=20)
        model = load_model()
        if model is None:
            st.error("No trained model found — run `python main.py` once to bootstrap it, or train via processing.banknote_cnn.train().")
        else:
            sample = glob.glob(os.path.join(data_dir, "counterfeit", "*.png"))[0]
            result = analyze_banknote(sample, model)
            st.image(sample, width=200)
            st.json(result)
    elif uploaded is not None:
        from processing.banknote_cnn import load_model, analyze_banknote
        model = load_model()
        if model is None:
            st.error("No trained model found — run `python main.py` once to bootstrap it.")
        else:
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
                f.write(uploaded.read())
                tmp_path = f.name
            result = analyze_banknote(tmp_path, model)
            st.image(uploaded, width=200)
            st.json(result)
