# app.py — Suspicious Login Pattern Analyzer (fixed GitHub/Local paths)

from __future__ import annotations
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

# ============================================================
# Page setup
# ============================================================
st.set_page_config(page_title="Suspicious Login Analyzer", page_icon="🔐", layout="wide")

# ============================================================
# Sidebar — Source & Controls
# ============================================================
st.sidebar.title("Data Source")
source = st.sidebar.radio("Load reports from:", ["Local (Reports/)", "GitHub (raw)"])

st.sidebar.header("Display / Rules")
top_n        = st.sidebar.slider("Show top N rows", 5, 100, 30, 5)
host_thresh  = st.sidebar.number_input("Flag users with > N distinct hosts", value=50, min_value=1)
events_thresh= st.sidebar.number_input("Flag users with > N total events",   value=20000, min_value=1)
pair_thresh  = st.sidebar.number_input("Flag user–computer pairs with > N events", value=25000, min_value=1)
search_user  = st.sidebar.text_input("Filter by user (contains)", "")

if st.sidebar.button("🔄 Reload data"):
    st.cache_data.clear()

now_local = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
now_utc   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
st.sidebar.caption(f"**Now (local):** {now_local}\n\n**Now (UTC):** {now_utc}")

# ============================================================
# GitHub repo settings (used only when source = GitHub)
# ============================================================
USER, REPO, BRANCH = "aashishshah4815", "SuspiciousLoginAnalyzer", "main"

RAW_BASE     = f"https://raw.githubusercontent.com/{USER}/{REPO}/{BRANCH}"
REPORTS_BASE = f"{RAW_BASE}/Reports"
MODELS_BASE  = f"{RAW_BASE}/models"

def report_path(name: str) -> str:
    """Reports/<name> — local path or GitHub raw URL."""
    return f"{REPORTS_BASE}/{name}" if source.startswith("GitHub") else f"Reports/{name}"

def model_path(name: str) -> str:
    """models/<name> — local path or GitHub raw URL."""
    return f"{MODELS_BASE}/{name}" if source.startswith("GitHub") else f"models/{name}"

# ============================================================
# Robust loaders
# ============================================================
@st.cache_data(ttl=300, show_spinner=False)
def _read_csv(path: str) -> pd.DataFrame:
    """Reads CSV from local path or URL. Raises on error."""
    # When using GitHub raw URLs, let pandas fetch via HTTP(S)
    if path.startswith("http://") or path.startswith("https://"):
        return pd.read_csv(path)
    # Local file
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        raise FileNotFoundError(f"Missing or empty file: {p}")
    return pd.read_csv(p)

@st.cache_data(ttl=300, show_spinner=False)
def _read_json(path: str) -> Optional[dict]:
    """Reads JSON from local path or URL. Returns None on error."""
    try:
        if path.startswith("http"):
            # requests for clearer errors across Streamlit hosting
            r = requests.get(path, timeout=20)
            r.raise_for_status()
            return r.json()
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None

def load_first_ok(label: str, candidates: List[str]) -> Tuple[Optional[pd.DataFrame], Optional[str], List[str]]:
    """
    Try a list of candidate paths (URLs or local). Return (df, error_message, tried_paths).
    """
    tried = []
    for c in candidates:
        tried.append(c)
        try:
            df = _read_csv(c)
            if df is not None and not df.empty:
                return df, None, tried
        except Exception as e:
            last_err = f"{label} failed to load from {c}: {e}"
    # If we got here, all failed
    return None, last_err if 'last_err' in locals() else f"{label} not found.", tried

# ============================================================
# Core datasets
# ============================================================
pairs, err_pairs, tried_pairs = load_first_ok(
    "TopUserComputerPairs",
    [report_path("TopUserComputerPairs.csv")]
)

users_dist, err_dist, tried_dist = load_first_ok(
    "TopUsers_ByDistinctComputers",
    [report_path("TopUsers_ByDistinctComputers.csv")]
)

users_events, err_events, tried_events = load_first_ok(
    "TopUsers_ByEvents",
    [report_path("TopUsers_ByEvents.csv")]
)

meta = _read_json(report_path("meta.json"))

# Suspicious findings (optional)
suspicious, err_susp, _ = load_first_ok(
    "SuspiciousFindings",
    [report_path("SuspiciousFindings.csv")]
)

# ============================================================
# ML artifacts — FIXED: look in Reports/ AND models/ for both sources
# ============================================================
# Unsupervised (AnomalyScores.csv): try Reports/ then models/
ml_unsup, err_unsup, tried_unsup = load_first_ok(
    "Unsupervised scores (AnomalyScores.csv)",
    [
        report_path("AnomalyScores.csv"),         # if you copied scores into Reports/
        model_path("AnomalyScores.csv"),          # canonical location from training: models/
    ]
)

# Supervised (ML_Findings_Supervised.csv): Reports/ only by design
ml_sup, err_sup, tried_sup = load_first_ok(
    "Supervised scores (ML_Findings_Supervised.csv)",
    [report_path("ML_Findings_Supervised.csv")]
)

# ============================================================
# Header & KPIs
# ============================================================
st.markdown(
    """
    <div style="display:flex;align-items:center;gap:12px;">
      <div style="font-size:28px">🔐 <b>Suspicious Login Pattern Analyzer</b></div>
    </div>
    """,
    unsafe_allow_html=True,
)

c1, c2, c3, c4 = st.columns(4)
if meta:
    c1.metric("Processed lines",  f"{meta.get('processed_lines', 0):,}")
    c2.metric("Unique users",     f"{meta.get('unique_users', 0):,}")
    c3.metric("Unique computers", f"{meta.get('unique_computers', 0):,}")
    c4.metric("Rich fields", "Yes" if meta.get("rich_fields_detected") else "No")
    st.caption("KPIs from meta.json (accurate for the processed slice).")
else:
    users_in_report    = (users_dist["User"].nunique() if users_dist is not None and "User" in users_dist else 0)
    computers_in_pairs = (pairs["Computer"].nunique() if pairs is not None and "Computer" in pairs else 0)
    max_user_events    = (int(users_events["TotalEvents"].max()) if users_events is not None and "TotalEvents" in users_events else 0)
    max_user_hosts     = (int(users_dist["DistinctComputers"].max()) if users_dist is not None and "DistinctComputers" in users_dist else 0)
    c1.metric("Users in report",        f"{users_in_report:,}")
    c2.metric("Computers in pairs",     f"{computers_in_pairs:,}")
    c3.metric("Max user events",        f"{max_user_events:,}")
    c4.metric("Max distinct computers", f"{max_user_hosts:,}")
    st.caption("KPIs reflect top-K summaries (fallback).")

st.divider()

# ============================================================
# Top pairs
# ============================================================
st.subheader("📈 Top User–Computer Pairs")
if err_pairs and (pairs is None or pairs.empty):
    with st.expander("Why no pair data?", expanded=False):
        st.code("\n".join(tried_pairs or []), language="text")
        st.error(err_pairs)
elif pairs is None or pairs.empty:
    st.info("No pair data available.")
else:
    df_pairs = pairs.copy()
    if search_user:
        df_pairs = df_pairs[df_pairs["User"].astype(str).str.contains(search_user, case=False, na=False)]
    df_pairs = df_pairs.head(top_n)

    st.dataframe(df_pairs, use_container_width=True, height=360)

    agg = df_pairs.groupby("User", as_index=False)["Events"].sum().sort_values("Events", ascending=False)
    fig1 = px.bar(agg, x="User", y="Events", title="Events by User (Top pairs)", text="Events")
    fig1.update_traces(texttemplate="%{text:,}", hovertemplate="User: %{x}<br>Events: %{y:,}")
    st.plotly_chart(fig1, use_container_width=True)

    st.download_button(
        "Download full pairs CSV",
        pairs.to_csv(index=False).encode("utf-8"),
        file_name="TopUserComputerPairs.csv",
        mime="text/csv",
    )

st.divider()

# ============================================================
# Tabs
# ============================================================
tab1, tab2, tab3, tabML, tabMap = st.tabs(
    ["🧭 Users by Distinct Computers", "⚡ Users by Total Events", "🚩 Suspicious Findings", "🧠 ML Scores", "🌍 Geo Map"]
)

# --- Distinct computers ---
with tab1:
    if err_dist and (users_dist is None or users_dist.empty):
        with st.expander("Why no distinct-computers data?", expanded=False):
            st.code("\n".join(tried_dist or []), language="text")
            st.error(err_dist)
    elif users_dist is None or users_dist.empty:
        st.info("No distinct-computers data available.")
    else:
        df = users_dist.copy()
        if search_user:
            df = df[df["User"].astype(str).str.contains(search_user, case=False, na=False)]
        df_top = df.sort_values(["DistinctComputers","TotalEvents"], ascending=False).head(top_n)

        left, right = st.columns([2, 1])
        with left:
            st.dataframe(df_top, use_container_width=True, height=360)
        with right:
            fig = px.bar(
                df_top.sort_values("DistinctComputers", ascending=False),
                x="User", y="DistinctComputers",
                title="Distinct computers per user", text="DistinctComputers"
            )
            fig.update_traces(texttemplate="%{text}")
            st.plotly_chart(fig, use_container_width=True)

        st.download_button(
            "Download full CSV",
            users_dist.to_csv(index=False).encode("utf-8"),
            file_name="TopUsers_ByDistinctComputers.csv",
            mime="text/csv",
        )

# --- Total events ---
with tab2:
    if err_events and (users_events is None or users_events.empty):
        with st.expander("Why no total-events data?", expanded=False):
            st.code("\n".join(tried_events or []), language="text")
            st.error(err_events)
    elif users_events is None or users_events.empty:
        st.info("No total-events data available.")
    else:
        df = users_events.copy()
        if search_user:
            df = df[df["User"].astype(str).str.contains(search_user, case=False, na=False)]
        df_top = df.sort_values(["TotalEvents","User"], ascending=[False, True]).head(top_n)

        left, right = st.columns([2, 1])
        with left:
            st.dataframe(df_top, use_container_width=True, height=360)
        with right:
            fig = px.bar(
                df_top.sort_values("TotalEvents", ascending=False),
                x="User", y="TotalEvents",
                title="Total events per user", text="TotalEvents"
            )
            fig.update_traces(texttemplate="%{text:,}")
            st.plotly_chart(fig, use_container_width=True)

        st.download_button(
            "Download full CSV",
            users_events.to_csv(index=False).encode("utf-8"),
            file_name="TopUsers_ByEvents.csv",
            mime="text/csv",
        )

# --- Suspicious findings ---
with tab3:
    st.caption(f"Thresholds: hosts>{host_thresh}, user events>{events_thresh}, pair events>{pair_thresh}")
    if suspicious is None or suspicious.empty:
        if err_susp:
            with st.expander("Why no suspicious findings?", expanded=False):
                st.error(err_susp)
        st.info("No suspicious findings (or file missing).")
    else:
        df_all = suspicious.copy()

        # Flags
        if "DistinctComputers" in df_all.columns:
            mask = (df_all.get("Rule") == "DistinctHosts") & (df_all["DistinctComputers"] > host_thresh)
            df_all.loc[mask, "Flag"] = "Host threshold"
        if "TotalEvents" in df_all.columns:
            mask = (df_all.get("Rule") == "TotalEvents") & (df_all["TotalEvents"] > events_thresh)
            df_all.loc[mask, "Flag"] = "User events threshold"
        if "Events" in df_all.columns:
            mask = (df_all.get("Rule") == "HotPair") & (df_all["Events"] > pair_thresh)
            df_all.loc[mask, "Flag"] = "Pair events threshold"

        if search_user:
            df_all = df_all[df_all.get("User", "").astype(str).str.contains(search_user, case=False, na=False)]

        st.dataframe(df_all.head(400), use_container_width=True, height=420)

        st.download_button(
            "Download SuspiciousFindings CSV",
            df_all.to_csv(index=False).encode("utf-8"),
            file_name="SuspiciousFindings.csv",
            mime="text/csv",
        )

# --- ML Scores ---
with tabML:
    cU, cS = st.columns(2)

    # Unsupervised
    with cU:
        st.subheader("Unsupervised (IsolationForest + One-Class SVM)")
        if ml_unsup is None or ml_unsup.empty:
            st.info(
                "No unsupervised scores found. Train with:\n\n"
                "`python -m ml.train_unsupervised --reports Reports --outdir models`\n\n"
                "Looked for:\n"
                f"- {report_path('AnomalyScores.csv')}\n"
                f"- {model_path('AnomalyScores.csv')}"
            )
        else:
            df_u = ml_unsup.copy()
            if "User" in df_u.columns:
                if search_user:
                    df_u = df_u[df_u["User"].astype(str).str.contains(search_user, case=False, na=False)]
                if "EnsembleScore" in df_u.columns:
                    df_u = df_u.sort_values("EnsembleScore", ascending=False)
                df_u = df_u.head(top_n)
            st.dataframe(df_u, use_container_width=True, height=360)
            if {"User", "EnsembleScore"}.issubset(df_u.columns):
                figu = px.bar(df_u, x="User", y="EnsembleScore", title="Top anomalies (ensemble)", text="EnsembleScore")
                figu.update_traces(texttemplate="%{text:.3f}")
                st.plotly_chart(figu, use_container_width=True)

            st.download_button(
                "Download unsupervised scores CSV",
                ml_unsup.to_csv(index=False).encode("utf-8"),
                file_name="AnomalyScores.csv",
                mime="text/csv",
            )

    # Supervised
    with cS:
        st.subheader("Supervised (RandomForest)")
        if ml_sup is None or ml_sup.empty:
            st.info(
                "No supervised scores found. Train with:\n\n"
                "`python -m ml.train_supervised --reports Reports --outdir models`\n\n"
                "Looked for:\n"
                f"- {report_path('ML_Findings_Supervised.csv')}"
            )
        else:
            df_s = ml_sup.copy()
            if "User" in df_s.columns:
                if search_user:
                    df_s = df_s[df_s["User"].astype(str).str.contains(search_user, case=False, na=False)]
                # pick score column heuristically
                score_col = None
                for c in ("Sup_ProbBad", "prob", "score", "Score"):
                    if c in df_s.columns:
                        score_col = c
                        break
                if score_col:
                    df_s = df_s.sort_values(score_col, ascending=False)
                df_s = df_s.head(top_n)
            st.dataframe(df_s, use_container_width=True, height=360)

            # plot if we found a score column
            score_col = None
            for c in ("Sup_ProbBad", "prob", "score", "Score"):
                if c in df_s.columns:
                    score_col = c
                    break
            if score_col:
                figs = px.bar(df_s, x="User", y=score_col, title=f"Supervised scores ({score_col})", text=score_col)
                figs.update_traces(texttemplate="%{text:.3f}")
                st.plotly_chart(figs, use_container_width=True)

            st.download_button(
                "Download supervised scores CSV",
                ml_sup.to_csv(index=False).encode("utf-8"),
                file_name="ML_Findings_Supervised.csv",
                mime="text/csv",
            )

# --- Geo Map ---
with tabMap:
    if suspicious is None or suspicious.empty or "Country" not in (suspicious.columns if isinstance(suspicious, pd.DataFrame) else []):
        st.info("No geo data available for plotting.")
    else:
        df_geo = suspicious.copy()
        counts = df_geo["Country"].value_counts().reset_index()
        counts.columns = ["Country", "Count"]

        fig_map = px.choropleth(
            counts, locations="Country", locationmode="country names",
            color="Count", title="Suspicious logins by country",
            color_continuous_scale="Blues"
        )

        if {"Lat", "Lon"}.issubset(df_geo.columns):
            fig_map.add_trace(
                go.Scattergeo(
                    lon=df_geo["Lon"], lat=df_geo["Lat"],
                    text=(df_geo.get("User", "").astype(str) + " · " + df_geo["Country"].astype(str)),
                    mode="markers",
                    marker=dict(size=6, color="red", opacity=0.75),
                    name="Suspicious points"
                )
            )

        fig_map.update_layout(geo=dict(showland=True, landcolor="LightGray"))
        st.plotly_chart(fig_map, use_container_width=True)

        st.download_button(
            "Download findings used in map (CSV)",
            df_geo.to_csv(index=False).encode("utf-8"),
            file_name="SuspiciousFindings_Enriched.csv",
            mime="text/csv",
        )

# Footer
st.caption(
    f"Source: {'GitHub' if source.startswith('GitHub') else 'Local'} · "
    f"Repo: {USER}/{REPO} · Branch: {BRANCH} · "
    f"Rendered at {now_local} (local) / {now_utc}"
)
