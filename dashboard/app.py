"""
Streamlit dashboard for CA Threat Actor Profiler.
Run: streamlit run dashboard/app.py
"""
import sys
sys.path.insert(0, ".")

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
from storage.models import get_session, ActorProfile, IOC, RawDocument

st.set_page_config(page_title="CA Threat Actor Profiler", layout="wide")
st.title("Canada Threat Actor Profiler")
st.caption("OSINT-driven threat intelligence — Canadian infrastructure focus")

session = get_session()

# ── Sidebar filters ──────────────────────────────────────────────────────────
with st.sidebar:
    st.header("Filters")
    days_back = st.slider("Days back", 1, 90, 30)
    min_incidents = st.number_input("Min incidents per actor", 1, 50, 2)
    since = datetime.utcnow() - timedelta(days=days_back)

# ── Summary metrics ──────────────────────────────────────────────────────────
actors = session.query(ActorProfile).filter(ActorProfile.last_seen >= since).all()
total_docs = session.query(RawDocument).filter(RawDocument.canada_relevant == True).count()
total_iocs = session.query(IOC).count()

col1, col2, col3 = st.columns(3)
col1.metric("Actor Profiles", len(actors))
col2.metric("CA-Relevant Documents", total_docs)
col3.metric("Unique IOCs", total_iocs)

st.divider()

# ── Actor profiles table ─────────────────────────────────────────────────────
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

    # ── Detail panel ─────────────────────────────────────────────────────────
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

# ── Source breakdown chart ───────────────────────────────────────────────────
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
