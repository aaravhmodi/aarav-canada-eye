"""
Streamlit dashboard for CA Threat Actor Profiler + Counterfeit Currency Pattern Tracking.
Run: streamlit run dashboard/app.py
"""
from __future__ import annotations

import glob
import os
import sys
import tempfile
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, ".")

from config import cfg
from processing.counterfeit_analyzer import aggregate_patterns
from storage.models import ActorProfile, CounterfeitStat, CourtCase, IOC, RawDocument, get_session


st.set_page_config(page_title="CA OSINT Platform", layout="wide")


def apply_theme() -> None:
    st.markdown(
        """
        <style>
            :root {
                color-scheme: light;
                --app-bg: #f6f7f9;
                --panel: #ffffff;
                --ink: #172033;
                --muted: #667085;
                --line: #e4e7ec;
                --accent: #b42318;
                --accent-soft: #fff1f0;
                --focus: rgba(180, 35, 24, 0.18);
            }

            .stApp {
                background: var(--app-bg);
                color: var(--ink);
            }

            .stApp,
            .stApp p,
            .stApp label,
            .stApp span,
            .stApp div {
                color: var(--ink);
            }

            [data-testid="stSidebar"] {
                background: var(--panel);
                border-right: 1px solid var(--line);
            }

            [data-testid="stHeader"] {
                background: rgba(247, 248, 251, 0.86);
                backdrop-filter: blur(10px);
            }

            .block-container {
                padding-top: 2rem;
                padding-bottom: 3rem;
                max-width: 1280px;
            }

            h1, h2, h3, h4, h5, h6 {
                color: var(--ink);
                letter-spacing: 0;
            }

            .app-hero {
                background: var(--panel);
                border: 1px solid var(--line);
                border-radius: 8px;
                padding: 1.35rem 1.5rem;
                margin-bottom: 1rem;
                box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
            }

            .eyebrow {
                color: var(--accent);
                font-size: 0.78rem;
                font-weight: 700;
                letter-spacing: 0;
                text-transform: uppercase;
                margin-bottom: 0.35rem;
            }

            .app-hero h1 {
                color: var(--ink);
                font-size: 2rem;
                line-height: 1.15;
                margin: 0 0 0.35rem 0;
                letter-spacing: 0;
            }

            .app-hero p {
                color: var(--muted);
                max-width: 760px;
                margin: 0;
                font-size: 1rem;
            }

            [data-testid="stMetric"] {
                background: var(--panel);
                border: 1px solid var(--line);
                border-radius: 8px;
                padding: 1rem 1.05rem;
                box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
            }

            [data-testid="stMetricLabel"] {
                color: var(--muted);
                font-size: 0.82rem;
            }

            [data-testid="stMetricValue"] {
                color: var(--ink);
                font-size: 1.65rem;
            }

            div[data-testid="stTabs"] button {
                color: #344054;
                font-weight: 600;
            }

            div[data-testid="stTabs"] [role="tablist"] {
                border-bottom: 1px solid var(--line);
                gap: 0.5rem;
            }

            div[data-testid="stTabs"] [role="tab"] {
                background: transparent;
                border-radius: 6px 6px 0 0;
                color: #344054;
                padding: 0.65rem 0.85rem;
            }

            div[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
                background: #ffffff;
                border: 1px solid var(--line);
                border-bottom-color: #ffffff;
                color: var(--accent);
            }

            .section-title {
                margin-top: 0.4rem;
                margin-bottom: 0.3rem;
            }

            .section-title h2 {
                color: var(--ink);
                font-size: 1.15rem;
                margin: 0;
                letter-spacing: 0;
            }

            .section-title p {
                color: var(--muted);
                margin: 0.2rem 0 0 0;
                font-size: 0.92rem;
            }

            .callout {
                background: var(--accent-soft);
                border: 1px solid #fecdca;
                border-radius: 8px;
                color: #7a271a;
                padding: 0.95rem 1rem;
                margin: 0.25rem 0 1rem 0;
            }

            .muted-note {
                color: var(--muted);
                font-size: 0.9rem;
            }

            .stDataFrame {
                border: 1px solid var(--line);
                border-radius: 8px;
                overflow: hidden;
                background: var(--panel);
            }

            [data-testid="stDataFrame"] div,
            [data-testid="stTable"] div {
                background-color: #ffffff;
                color: var(--ink);
            }

            [data-testid="stSelectbox"] > div,
            [data-testid="stNumberInput"] > div,
            [data-testid="stFileUploader"] section {
                background: #ffffff;
                border-color: var(--line);
                color: var(--ink);
            }

            [data-testid="stSlider"] [data-baseweb="slider"] {
                color: var(--accent);
            }

            .stButton button,
            .stLinkButton a {
                background: var(--accent);
                border: 1px solid var(--accent);
                border-radius: 6px;
                color: #ffffff;
                font-weight: 700;
            }

            .stButton button:hover,
            .stLinkButton a:hover {
                background: #8f1d14;
                border-color: #8f1d14;
                color: #ffffff;
            }

            .stButton button:focus,
            .stLinkButton a:focus {
                box-shadow: 0 0 0 3px var(--focus);
            }

            hr {
                margin: 1.45rem 0;
                border-color: var(--line);
            }

            [data-testid="stAlert"] {
                background: #ffffff;
                border: 1px solid var(--line);
                color: var(--ink);
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def section(title: str, subtitle: str | None = None) -> None:
    sub = f"<p>{subtitle}</p>" if subtitle else ""
    st.markdown(f'<div class="section-title"><h2>{title}</h2>{sub}</div>', unsafe_allow_html=True)


def format_date(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "-"


def plot_template():
    return dict(
        template="plotly_white",
        color_discrete_sequence=["#b42318", "#0f766e", "#475467", "#d97706", "#2563eb"],
    )


def style_figure(fig):
    fig.update_layout(
        paper_bgcolor="#ffffff",
        plot_bgcolor="#ffffff",
        font=dict(color="#172033", family="Arial, sans-serif"),
        xaxis=dict(gridcolor="#eef0f3", zerolinecolor="#e4e7ec"),
        yaxis=dict(gridcolor="#eef0f3", zerolinecolor="#e4e7ec"),
    )
    return fig


def actor_dataframe(actors: list[ActorProfile]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Actor": actor.actor_label,
                "Incidents": actor.incident_count,
                "IPs": len(actor.ips or []),
                "Domains": len(actor.domains or []),
                "Hashes": len(actor.hashes or []),
                "TTPs": len(actor.ttps or []),
                "First seen": format_date(actor.first_seen),
                "Last seen": format_date(actor.last_seen),
                "MISP": "Linked" if actor.misp_event_uuid else "-",
            }
            for actor in actors
        ]
    )


def render_header() -> None:
    st.markdown(
        """
        <div class="app-hero">
            <div class="eyebrow">Canada OSINT Platform</div>
            <h1>Operational intelligence dashboard</h1>
            <p>
                Monitor Canadian threat intelligence collection, actor profiles, IOCs,
                counterfeit-currency statistics, anomaly signals, and demo banknote scans.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_threat_tab(session) -> None:
    with st.sidebar:
        st.header("Filters")
        days_back = st.slider("Days back", 1, 90, 30)
        min_incidents = st.number_input("Minimum actor incidents", 1, 50, 2)

    since = datetime.utcnow() - timedelta(days=days_back)
    actors = session.query(ActorProfile).filter(ActorProfile.last_seen >= since).all()
    total_docs = session.query(RawDocument).filter(RawDocument.canada_relevant == True).count()
    total_iocs = session.query(IOC).count()
    filtered = [actor for actor in actors if actor.incident_count >= min_incidents]

    metric_cols = st.columns(4)
    metric_cols[0].metric("Actor profiles", f"{len(filtered):,}", help="Profiles matching the active filters.")
    metric_cols[1].metric("CA documents", f"{total_docs:,}", help="Collected documents marked Canada-relevant.")
    metric_cols[2].metric("Unique IOCs", f"{total_iocs:,}", help="Indicators currently stored in the IOC table.")
    metric_cols[3].metric("Lookback", f"{days_back} days")

    st.divider()
    section("Actor Profiles", "Prioritized profiles from recent Canadian-relevant collection.")

    if not filtered:
        st.info("No actor profiles match the current filters.")
    else:
        df = actor_dataframe(filtered)
        st.dataframe(df, use_container_width=True, hide_index=True)

        selected = st.selectbox("Inspect actor", df["Actor"].tolist())
        actor = next(item for item in filtered if item.actor_label == selected)

        detail_cols = st.columns(3)
        detail_cols[0].dataframe(pd.DataFrame({"IP": actor.ips or []}), use_container_width=True, hide_index=True)
        detail_cols[1].dataframe(
            pd.DataFrame({"Domain": actor.domains or []}), use_container_width=True, hide_index=True
        )
        detail_cols[2].dataframe(pd.DataFrame({"TTP": actor.ttps or []}), use_container_width=True, hide_index=True)

        if actor.misp_event_uuid:
            misp_url = f"{cfg['misp']['url']}/events/view/{actor.misp_event_uuid}"
            st.link_button("Open MISP event", misp_url)

    st.divider()
    section("Collection Sources", "Distribution of Canada-relevant documents by source type.")
    source_counts = (
        session.query(RawDocument.source_type)
        .filter(RawDocument.canada_relevant == True)
        .all()
    )
    if source_counts:
        src_df = pd.DataFrame(source_counts, columns=["Source"])
        fig = px.histogram(src_df, y="Source", color="Source", **plot_template())
        fig.update_layout(showlegend=False, height=340, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(style_figure(fig), use_container_width=True)
    else:
        st.caption("No Canada-relevant collection rows are available yet.")


def render_counterfeit_tab(session) -> None:
    st.markdown(
        """
        <div class="callout">
            Counterfeit statistics are based on scraped RCMP public tables. The banknote scanner
            is a synthetic-data pipeline demo and should not be treated as a real fraud signal.
        </div>
        """,
        unsafe_allow_html=True,
    )

    stats_rows = session.query(CounterfeitStat).all()
    if not stats_rows:
        st.warning("No counterfeit stats collected yet. Run `python main.py` or the scheduled collection task first.")
    else:
        stats_dicts = [
            {
                "year": stat.year,
                "province": stat.province,
                "denomination": stat.denomination,
                "passed": stat.passed,
                "seized": stat.seized,
            }
            for stat in stats_rows
        ]
        patterns = aggregate_patterns(stats_dicts)

        years = sorted(patterns["by_year"])
        latest_year = years[-1]
        latest = patterns["by_year"][latest_year]
        prev = patterns["by_year"].get(latest_year - 1, {"passed": 0, "seized": 0})
        current_total = latest["passed"] + latest["seized"]
        prev_total = prev["passed"] + prev["seized"]
        yoy_pct = ((current_total - prev_total) / max(prev_total, 1)) * 100

        metric_cols = st.columns(4)
        metric_cols[0].metric(f"{latest_year} passed", f"{latest['passed']:,}")
        metric_cols[1].metric(f"{latest_year} seized", f"{latest['seized']:,}")
        metric_cols[2].metric("Year-over-year", f"{yoy_pct:+.0f}%")
        metric_cols[3].metric("Court cases", f"{session.query(CourtCase).count():,}")

        for anomaly in patterns["anomalies"]:
            st.warning(
                f"Anomalous spike in {anomaly['year']}: total activity {anomaly['value']:,} "
                f"vs. baseline mean {anomaly['baseline_mean']:,.0f} (z-score {anomaly['z_score']})."
            )

        st.divider()
        section("National Trend", "Passed into circulation compared with notes seized before circulation.")
        trend_df = pd.DataFrame(
            [
                {
                    "Year": year,
                    "Passed into circulation": values["passed"],
                    "Seized by law enforcement": values["seized"],
                }
                for year, values in sorted(patterns["by_year"].items())
            ]
        )
        fig = px.bar(
            trend_df,
            x="Year",
            y=["Passed into circulation", "Seized by law enforcement"],
            barmode="group",
            **plot_template(),
        )
        fig.update_layout(height=380, legend_title_text="", margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(style_figure(fig), use_container_width=True)

        st.divider()
        breakdown_cols = st.columns(2)
        with breakdown_cols[0]:
            section("By Province")
            prov_df = pd.DataFrame(
                [
                    {"Province": province, "Passed": values["passed"], "Seized": values["seized"]}
                    for province, values in patterns["by_province"].items()
                ]
            ).sort_values("Seized", ascending=False)
            st.dataframe(prov_df, use_container_width=True, hide_index=True)
        with breakdown_cols[1]:
            section("By Denomination")
            denom_df = pd.DataFrame(
                [
                    {"Denomination": denomination, "Passed": values["passed"], "Seized": values["seized"]}
                    for denomination, values in patterns["by_denomination"].items()
                ]
            ).sort_values("Seized", ascending=False)
            st.dataframe(denom_df, use_container_width=True, hide_index=True)

        st.divider()
        section("Court Cases", "CanLII case metadata related to Canadian counterfeit currency offences.")
        cases = session.query(CourtCase).all()
        if cases:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Case": case.case_name,
                            "Jurisdiction": case.jurisdiction,
                            "Date": format_date(case.decision_date),
                            "URL": case.url,
                        }
                        for case in cases
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("No court cases collected yet. Set `CANLII_API_KEY` in `.env` to enable collection.")

    st.divider()
    section("Banknote Scanner", "Upload a note image or run the synthetic sample workflow.")
    uploaded = st.file_uploader("Upload note image", type=["png", "jpg", "jpeg"])
    generate_sample = st.button("Generate sample scan", use_container_width=True)

    if generate_sample:
        from processing.banknote_cnn import analyze_banknote, generate_synthetic_demo_dataset, load_model

        data_dir = generate_synthetic_demo_dataset(n_samples=20)
        model = load_model()
        if model is None:
            st.error("No trained model found. Run `python main.py` once to bootstrap it.")
        else:
            sample = glob.glob(os.path.join(data_dir, "counterfeit", "*.png"))[0]
            result = analyze_banknote(sample, model)
            st.image(sample, width=260)
            st.json(result)
    elif uploaded is not None:
        from processing.banknote_cnn import analyze_banknote, load_model

        model = load_model()
        if model is None:
            st.error("No trained model found. Run `python main.py` once to bootstrap it.")
        else:
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as file:
                file.write(uploaded.read())
                tmp_path = file.name
            result = analyze_banknote(tmp_path, model)
            st.image(uploaded, width=260)
            st.json(result)


apply_theme()
render_header()

session = get_session()
tab_threat, tab_counterfeit = st.tabs(["Threat Actors", "Counterfeit Currency"])

with tab_threat:
    render_threat_tab(session)

with tab_counterfeit:
    render_counterfeit_tab(session)
