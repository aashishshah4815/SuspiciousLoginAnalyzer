import streamlit as st
import pandas as pd

st.set_page_config(page_title="Suspicious Login Analyzer", page_icon="🔐", layout="wide")

# ---------------- Sidebar: data source ----------------
st.sidebar.title("Data Source")
source = st.sidebar.radio("Load reports from:", ["Local (Reports/)", "GitHub (raw)"])

USER   = "aashishshah4815"
REPO   = "SuspiciousLoginAnalyzer"
BRANCH = "main"
BASE   = f"https://raw.githubusercontent.com/{USER}/{REPO}/{BRANCH}/Reports"

def url_for(name): return f"{BASE}/{name}"

def get_paths():
    if source.startswith("GitHub"):
        return {
            "distinct": url_for("TopUsers_ByDistinctComputers.csv"),
            "events":   url_for("TopUsers_ByEvents.csv"),
            "pairs":    url_for("TopUserComputerPairs.csv"),
        }
    else:
        return {
            "distinct": "Reports/TopUsers_ByDistinctComputers.csv",
            "events":   "Reports/TopUsers_ByEvents.csv",
            "pairs":    "Reports/TopUserComputerPairs.csv",
        }

paths = get_paths()

@st.cache_data(ttl=300)
def load_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path)

def safe_load(label, path):
    try:
        df = load_csv(path)
        return df, None
    except Exception as e:
        return None, f"❗ {label} failed to load: {e}"

# ---------------- Load data ----------------
pairs, err_pairs       = safe_load("TopUserComputerPairs", paths["pairs"])
users_dist, err_dist   = safe_load("TopUsers_ByDistinctComputers", paths["distinct"])
users_events, err_evts = safe_load("TopUsers_ByEvents", paths["events"])

st.title("🔐 Suspicious Login Pattern Analyzer")

# ---------------- Hero section: Top pairs first ----------------
st.subheader("📊 Top User–Computer Pairs")
if err_pairs: st.error(err_pairs)
if pairs is not None and not pairs.empty:
    c1, c2, c3 = st.columns(3)
    total_pairs = len(pairs)
    top_pair = pairs.iloc[0] if total_pairs > 0 else None
    c1.metric("Rows Loaded", f"{total_pairs:,}")
    c2.metric("Top Pair Events", f"{int(top_pair['Events']):,}" if top_pair is not None else "—")
    c3.metric("Top Pair", f"{top_pair['User']} → {top_pair['Computer']}" if top_pair is not None else "—")

    st.dataframe(pairs.head(50), use_container_width=True)
    st.bar_chart(pairs.set_index("User")["Events"].head(20))

    st.download_button("Download pairs (CSV)", pairs.to_csv(index=False).encode("utf-8"),
                       file_name="TopUserComputerPairs.csv", mime="text/csv")
else:
    st.info("No pair data available.")

st.divider()

# ---------------- Tabs for user summaries ----------------
tab1, tab2 = st.tabs(["Users by Distinct Computers", "Users by Total Events"])

with tab1:
    st.subheader("🧭 Users by Distinct Computers")
    if err_dist: st.error(err_dist)
    if users_dist is not None and not users_dist.empty:
        left, right = st.columns([2, 1])
        with left:  st.dataframe(users_dist.head(50), use_container_width=True)
        with right: st.bar_chart(users_dist.set_index("User")["DistinctComputers"].head(20))
        st.download_button("Download (CSV)", users_dist.to_csv(index=False).encode("utf-8"),
                           file_name="TopUsers_ByDistinctComputers.csv", mime="text/csv")
    else:
        st.info("No distinct-computers data available.")

with tab2:
    st.subheader("⚡ Users by Total Events")
    if err_evts: st.error(err_evts)
    if users_events is not None and not users_events.empty:
        left, right = st.columns([2, 1])
        with left:  st.dataframe(users_events.head(50), use_container_width=True)
        with right: st.bar_chart(users_events.set_index("User")["TotalEvents"].head(20))
        st.download_button("Download (CSV)", users_events.to_csv(index=False).encode("utf-8"),
                           file_name="TopUsers_ByEvents.csv", mime="text/csv")
    else:
        st.info("No total-events data available.")

st.caption(
    f"Source: {'GitHub' if source.startswith('GitHub') else 'Local'} · "
    f"Repo: {USER}/{REPO} · Branch: {BRANCH}"
)
