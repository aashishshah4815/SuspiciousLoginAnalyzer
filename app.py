# app.py
import json
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ========================== CONFIG ==========================
st.set_page_config(page_title="Suspicious Login Analyzer", page_icon="🔐", layout="wide")

# ========================== SIDEBAR ==========================
st.sidebar.title("Data Source")
source = st.sidebar.radio("Load reports from:", ["Local (Reports/)", "GitHub (raw)"])

st.sidebar.header("Display / Rules")
top_n = st.sidebar.slider("Show top N rows", 5, 100, 30, 5)
host_thresh   = st.sidebar.number_input("Flag users with > N distinct hosts", value=50, min_value=1)
events_thresh = st.sidebar.number_input("Flag users with > N total events",   value=20000, min_value=1)
pair_thresh   = st.sidebar.number_input("Flag user–computer pairs with > N events", value=25000, min_value=1)

search_user = st.sidebar.text_input("Filter by user (contains)", "")

if st.sidebar.button("🔄 Reload data"):
    st.cache_data.clear()

now_local = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
now_utc   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
st.sidebar.caption(f"**Now (local):** {now_local}\n\n**Now (UTC):** {now_utc}")

# ========================== PATHS & LOADERS ==========================
USER, REPO, BRANCH = "aashishshah4815", "SuspiciousLoginAnalyzer", "main"
BASE = f"https://raw.githubusercontent.com/{USER}/{REPO}/{BRANCH}/Reports"

def path_for(name: str) -> str:
    return f"{BASE}/{name}" if source.startswith("GitHub") else f"Reports/{name}"

@st.cache_data(ttl=300)
def load_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path)

@st.cache_data(ttl=300)
def load_meta(path: str):
    try:
        if path.startswith("http"):
            return json.loads(pd.read_json(path).to_json())
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def load_safe(label, name):
    try:
        df = load_csv(path_for(name))
        return df, None
    except Exception as e:
        return None, f"❗ {label} failed to load: {e}"

pairs, err_pairs         = load_safe("TopUserComputerPairs", "TopUserComputerPairs.csv")
users_dist, err_dist     = load_safe("TopUsers_ByDistinctComputers", "TopUsers_ByDistinctComputers.csv")
users_events, err_events = load_safe("TopUsers_ByEvents", "TopUsers_ByEvents.csv")
meta = load_meta(path_for("meta.json"))

try:
    suspicious = load_csv(path_for("SuspiciousFindings.csv"))
except Exception:
    suspicious = None

# ========================== HEADER ==========================
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

# ========================== MAIN CONTENT ==========================
st.subheader("📈 Top User–Computer Pairs")
if err_pairs: st.error(err_pairs)
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

# ========================== TABS ==========================
tab1, tab2, tab3, tab4 = st.tabs(
    ["🧭 Users by Distinct Computers", "⚡ Users by Total Events", "🚩 Suspicious Findings", "🌍 Geo Map"]
)

with tab1:
    if err_dist: st.error(err_dist)
    elif users_dist is None or users_dist.empty:
        st.info("No distinct-computers data available.")
    else:
        df = users_dist.copy()
        if search_user:
            df = df[df["User"].astype(str).str.contains(search_user, case=False, na=False)]
        df_top = df.sort_values(["DistinctComputers","TotalEvents"], ascending=False).head(top_n)

        left, right = st.columns([2, 1])
        with left: st.dataframe(df_top, use_container_width=True, height=360)
        with right:
            fig = px.bar(df_top.sort_values("DistinctComputers", ascending=False),
                         x="User", y="DistinctComputers", title="Distinct computers per user", text="DistinctComputers")
            st.plotly_chart(fig, use_container_width=True)

        st.download_button("Download full CSV",
                           users_dist.to_csv(index=False).encode("utf-8"),
                           file_name="TopUsers_ByDistinctComputers.csv",
                           mime="text/csv")

with tab2:
    if err_events: st.error(err_events)
    elif users_events is None or users_events.empty:
        st.info("No total-events data available.")
    else:
        df = users_events.copy()
        if search_user:
            df = df[df["User"].astype(str).str.contains(search_user, case=False, na=False)]
        df_top = df.sort_values(["TotalEvents","User"], ascending=[False, True]).head(top_n)

        left, right = st.columns([2, 1])
        with left: st.dataframe(df_top, use_container_width=True, height=360)
        with right:
            fig = px.bar(df_top.sort_values("TotalEvents", ascending=False),
                         x="User", y="TotalEvents", title="Total events per user", text="TotalEvents")
            st.plotly_chart(fig, use_container_width=True)

        st.download_button("Download full CSV",
                           users_events.to_csv(index=False).encode("utf-8"),
                           file_name="TopUsers_ByEvents.csv",
                           mime="text/csv")

with tab3:
    if suspicious is None or suspicious.empty:
        st.info("No suspicious findings (or file missing).")
    else:
        df_all = suspicious.copy()
        if "DistinctComputers" in df_all.columns:
            df_all.loc[(df_all.get("Rule")=="DistinctHosts") & (df_all["DistinctComputers"] > host_thresh), "Flag"] = "Host threshold"
        if "TotalEvents" in df_all.columns:
            df_all.loc[(df_all.get("Rule")=="TotalEvents") & (df_all["TotalEvents"] > events_thresh), "Flag"] = "User events threshold"
        if "Events" in df_all.columns:
            df_all.loc[(df_all.get("Rule")=="HotPair") & (df_all["Events"] > pair_thresh), "Flag"] = "Pair events threshold"

        if search_user:
            df_all = df_all[df_all.get("User","").astype(str).str.contains(search_user, case=False, na=False)]

        st.dataframe(df_all.head(400), use_container_width=True, height=420)

        st.download_button("Download SuspiciousFindings CSV",
                           df_all.to_csv(index=False).encode("utf-8"),
                           file_name="SuspiciousFindings.csv",
                           mime="text/csv")

with tab4:
    if suspicious is None or suspicious.empty or "Country" not in suspicious.columns:
        st.info("No geo data available for plotting.")
    else:
        df_geo = suspicious.copy()

        # Aggregated country counts
        counts = df_geo["Country"].value_counts().reset_index()
        counts.columns = ["Country", "Count"]

        # Choropleth layer
        fig_map = px.choropleth(
            counts, locations="Country", locationmode="country names",
            color="Count", title="Suspicious logins by country",
            color_continuous_scale="Blues"
        )

        # Scatter (red dots)
        if {"Lat","Lon"}.issubset(df_geo.columns):
            fig_map.add_trace(
                go.Scattergeo(
                    lon=df_geo["Lon"], lat=df_geo["Lat"],
                    text=df_geo["User"] + " (" + df_geo["Country"].astype(str) + ")",
                    mode="markers",
                    marker=dict(size=6, color="red", opacity=0.7),
                    name="Suspicious Logins"
                )
            )

        fig_map.update_layout(geo=dict(showland=True, landcolor="LightGray"))

        st.plotly_chart(fig_map, use_container_width=True)

        st.download_button("Download enriched suspicious findings",
                           df_geo.to_csv(index=False).encode("utf-8"),
                           file_name="SuspiciousFindings_Enriched.csv",
                           mime="text/csv")

st.caption(f"Source: {'GitHub' if source.startswith('GitHub') else 'Local'} · Repo: {USER}/{REPO} · Branch: {BRANCH} · "
           f"Rendered at {now_local} (local) / {now_utc}")
