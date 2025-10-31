# app.py — Suspicious Login Analyzer (supervised + unsupervised + geo)
import streamlit as st
import pandas as pd
import joblib
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
from io import StringIO
import plotly.express as px

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="🔐 Suspicious Login Analyzer",
    layout="wide",
)

DATA_PATH = Path("data/rba-dataset-1000.csv")
MODEL_PATH = Path("models/suspicious_login_rf.pkl")

# =========================================================
# HELPERS
# =========================================================
@st.cache_resource
def load_model():
    if not MODEL_PATH.exists():
        return None
    return joblib.load(MODEL_PATH)

@st.cache_data
def load_default_data():
    if DATA_PATH.exists():
        return pd.read_csv(DATA_PATH)
    return pd.DataFrame()

def preprocess_for_model(df: pd.DataFrame) -> pd.DataFrame:
    df_pred = df.copy()
    if "Is Attack IP" in df_pred.columns:
        df_pred = df_pred.drop(columns=["Is Attack IP"])
    if "index" in df_pred.columns:
        df_pred = df_pred.drop(columns=["index"])
    if "Login Timestamp" in df_pred.columns:
        df_pred["Login Timestamp"] = pd.to_datetime(
            df_pred["Login Timestamp"], errors="coerce"
        )
        df_pred["login_hour"] = df_pred["Login Timestamp"].dt.hour
        df_pred = df_pred.drop(columns=["Login Timestamp"])
    return df_pred

# =========================================================
# LOAD MODEL + DATA
# =========================================================
clf = load_model()
if clf is None:
    st.error("❌ Model file not found at `models/suspicious_login_rf.pkl`.")
    st.stop()

st.title("🔐 Suspicious Login Analyzer")

# =========================================================
# SIDEBAR — DATA + CONTROLS
# =========================================================
st.sidebar.header("📁 Data Input")
uploaded_file = st.sidebar.file_uploader("Upload CSV (optional)", type=["csv"])
use_sample = st.sidebar.button("Use sample dataset (data/rba-dataset-1000.csv)")

st.sidebar.header("⚙️ Detection Settings")
threshold = st.sidebar.slider(
    "Suspicious score threshold",
    0.10, 0.90, 0.50, 0.05,
    help="Lower = more alerts, higher = fewer alerts",
)

st.sidebar.header("🧪 Unsupervised")
k_clusters = st.sidebar.slider("K for K-Means", 2, 7, 3)

# =========================================================
# LOAD DATA (upload > sample > default)
# =========================================================
if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    source_label = "uploaded CSV"
elif use_sample:
    df = load_default_data()
    source_label = "sample dataset"
else:
    df = load_default_data()
    source_label = "auto (data/rba-dataset-1000.csv)"

if df.empty:
    st.error("No data found. Please upload a CSV or put one at data/rba-dataset-1000.csv")
    st.stop()

st.caption(f"📦 Data source: **{source_label}** — rows: **{len(df):,}**")

# =========================================================
# PREDICT
# =========================================================
df_model_in = preprocess_for_model(df)
proba = clf.predict_proba(df_model_in)[:, 1]
preds = (proba >= threshold).astype(int)

df_results = df.copy()
df_results["Suspicious Score"] = proba.round(3)
df_results["Predicted"] = preds.astype(str)
df_results["Threshold Used"] = threshold

# =========================================================
# TABS
# =========================================================
tab_dash, tab_sup, tab_unsup, tab_geo = st.tabs(
    ["📊 Dashboard", "🧪 Supervised (with label)", "🧬 Unsupervised K-Means", "🌍 Geography"]
)

# =========================================================
# DASHBOARD
# =========================================================
with tab_dash:
    st.subheader("📄 Input Data (first 50)")
    st.dataframe(df.head(50), use_container_width=True)

    total = len(df_results)
    flagged = int((df_results["Predicted"] == "1").sum())
    flag_rate = (flagged / total * 100) if total else 0

    c1, c2, c3 = st.columns(3)
    c1.metric("Total logins analysed", total)
    c2.metric("Flagged as suspicious", flagged)
    c3.metric("Flag rate", f"{flag_rate:.1f}%")

    st.caption(f"Detection threshold **{threshold:.2f}** — adjust in sidebar.")

    st.write("### 🛡️ Prediction Results (top 300)")
    st.dataframe(
        df_results.sort_values("Suspicious Score", ascending=False).head(300),
        use_container_width=True,
    )

    # chart 1
    st.write("### 📊 Suspicious vs Normal (Predicted)")
    plot_df = df_results.copy()
    plot_df["Predicted"] = plot_df["Predicted"].astype(str)

    total_records = len(plot_df)
    if total_records < 500:
        fig_size = (6, 4)
        font_size = 12
        title_size = 16
    else:
        fig_size = (8, 5)
        font_size = 13
        title_size = 18

    counts = plot_df["Predicted"].value_counts().sort_index()
    labels = ["Normal (0)", "Suspicious (1)"]
    colors = ["#1F618D", "#C0392B"]

    sns.set_style("whitegrid")
    sns.set_context("talk")

    fig, ax = plt.subplots(figsize=fig_size)
    bars = sns.barplot(x=labels, y=counts.values, palette=colors, ax=ax)

    for bar in bars.patches:
        h = bar.get_height()
        pct = 100 * h / sum(counts.values)
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            h + (0.02 * h),
            f"{int(h)} ({pct:.1f}%)",
            ha="center",
            va="bottom",
            fontsize=font_size,
            weight="bold",
            color="#111",
        )

    ax.set_title("Suspicious vs Normal (Predicted)", fontsize=title_size, weight="bold")
    ax.set_xlabel("")
    ax.set_ylabel("Count", fontsize=font_size)
    ax.set_ylim(0, max(counts.values) * 1.2)
    sns.despine()
    plt.tight_layout()
    st.pyplot(fig)

    # chart 2
    st.write("### 📈 Suspicious Score Distribution")
    if total_records < 500:
        bins = 15
    elif total_records < 2000:
        bins = 25
    else:
        bins = 40

    fig2, ax2 = plt.subplots(figsize=fig_size)
    sns.histplot(df_results["Suspicious Score"], bins=bins, kde=True, color="#1F618D", ax=ax2)
    ax2.axvline(x=threshold, color="#C0392B", linestyle="--", linewidth=2, label=f"Threshold = {threshold:.2f}")
    ax2.set_title("Model Confidence for Logins", fontsize=title_size, weight="bold")
    ax2.set_xlabel("Suspicious Score (0=normal, 1=very suspicious)", fontsize=font_size)
    ax2.set_ylabel("Records", fontsize=font_size)
    ax2.legend()
    plt.tight_layout()
    st.pyplot(fig2)

    st.write("### 🔥 Top risky entities")
    col_r1, col_r2 = st.columns(2)

    if "IP Address" in df_results.columns:
        top_ips = (
            df_results[df_results["Predicted"] == "1"]
            .groupby("IP Address")["Suspicious Score"]
            .max()
            .sort_values(ascending=False)
            .head(10)
            .reset_index()
        )
        col_r1.write("**Top suspicious IPs**")
        col_r1.dataframe(top_ips, use_container_width=True)
    else:
        col_r1.info("No `IP Address` column.")

    if "User ID" in df_results.columns:
        top_users = (
            df_results[df_results["Predicted"] == "1"]
            .groupby("User ID")["Suspicious Score"]
            .max()
            .sort_values(ascending=False)
            .head(10)
            .reset_index()
        )
        col_r2.write("**Top suspicious users**")
        col_r2.dataframe(top_users, use_container_width=True)
    else:
        col_r2.info("No `User ID` column.")

    st.write("### 📥 Flagged rows")
    flagged_df = df_results[df_results["Predicted"] == "1"].copy()
    if not flagged_df.empty:
        st.dataframe(flagged_df, use_container_width=True, height=230)
        buf = StringIO()
        flagged_df.to_csv(buf, index=False)
        st.download_button(
            "⬇️ Download flagged CSV",
            buf.getvalue(),
            file_name="flagged_suspicious_logins.csv",
            mime="text/csv",
        )
    else:
        st.info("No rows flagged — lower threshold.")

# =========================================================
# SUPERVISED TAB
# =========================================================
with tab_sup:
    st.subheader("🧪 Supervised Evaluation")
    if "Is Attack IP" not in df.columns:
        st.info("This CSV has no `Is Attack IP` column — nothing to evaluate.")
    else:
        y_true = df["Is Attack IP"].astype(int).values
        y_pred = (df_results["Predicted"] == "1").astype(int).values

        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Accuracy", f"{acc:.3f}")
        m2.metric("Precision", f"{prec:.3f}")
        m3.metric("Recall", f"{rec:.3f}")
        m4.metric("F1 Score", f"{f1:.3f}")

        metric_df = pd.DataFrame(
            {"Metric": ["Accuracy", "Precision", "Recall", "F1"], "Score": [acc, prec, rec, f1]}
        )
        figm = px.bar(
            metric_df,
            x="Metric",
            y="Score",
            title="Supervised Metrics",
            text="Score",
            color="Metric",
            color_discrete_sequence=["#1F618D", "#148F77", "#B03A2E", "#6C3483"],
        )
        figm.update_traces(texttemplate="%{text:.3f}", textposition="outside")
        figm.update_yaxes(range=[0, 1])
        st.plotly_chart(figm, use_container_width=True)

        cm_df = pd.DataFrame(
            cm,
            index=["Actual 0 (Normal)", "Actual 1 (Attack IP)"],
            columns=["Pred 0 (Normal)", "Pred 1 (Suspicious)"],
        )
        st.write("Confusion matrix")
        st.dataframe(cm_df, use_container_width=True)

# =========================================================
# UNSUPERVISED TAB
# =========================================================
with tab_unsup:
    st.subheader("🧬 Unsupervised K-Means")

    clu_df = df_results.copy()
    if "Login Timestamp" in clu_df.columns and "login_hour" not in clu_df.columns:
        clu_df["Login Timestamp"] = pd.to_datetime(clu_df["Login Timestamp"], errors="coerce")
        clu_df["login_hour"] = clu_df["Login Timestamp"].dt.hour

    features = []
    if "Suspicious Score" in clu_df.columns:
        features.append("Suspicious Score")
    if "Round-Trip Time [ms]" in clu_df.columns:
        features.append("Round-Trip Time [ms]")
    if "login_hour" in clu_df.columns:
        features.append("login_hour")

    if not features:
        st.info("Not enough numeric features to cluster.")
    else:
        X = clu_df[features].fillna(0)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        km = KMeans(n_clusters=k_clusters, random_state=42, n_init="auto")
        clusters = km.fit_predict(X_scaled)
        clu_df["cluster"] = clusters

        ccounts = (
            clu_df["cluster"].value_counts().rename_axis("cluster").reset_index(name="count")
        )
        figk = px.bar(
            ccounts,
            x="cluster",
            y="count",
            title="Cluster sizes (K-Means)",
            text="count",
            color="cluster",
            color_discrete_sequence=px.colors.qualitative.Set2,
        )
        figk.update_traces(textposition="outside")
        st.plotly_chart(figk, use_container_width=True)

        if "Suspicious Score" in clu_df.columns:
            figk2, axk2 = plt.subplots(figsize=(7, 4))
            sns.boxplot(data=clu_df, x="cluster", y="Suspicious Score", palette="Dark2", ax=axk2)
            axk2.set_title("Suspicious Score by cluster")
            st.pyplot(figk2)

        st.dataframe(clu_df.head(200), use_container_width=True)

# =========================================================
# GEOGRAPHY TAB
# =========================================================
with tab_geo:
    st.subheader("🌍 Suspicious Logins — Geography")

    flagged_geo = df_results[df_results["Predicted"] == "1"].copy()

    if not flagged_geo.empty and "Country" in flagged_geo.columns:
        country_counts = (
            flagged_geo["Country"]
            .value_counts()
            .reset_index(name="suspicious_count")
            .rename(columns={"index": "Country"})
        )

        fig_map = px.scatter_geo(
            country_counts,
            locations="Country",
            locationmode="country names",
            size="suspicious_count",
            color="suspicious_count",
            hover_name="Country",
            projection="natural earth",
            title="Suspicious logins by country",
        )
        fig_map.update_traces(marker=dict(line=dict(width=0)))
        fig_map.update_layout(
            margin=dict(l=0, r=0, t=40, b=0),
            height=500,
        )
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("No flagged rows or no `Country` column to plot.")
