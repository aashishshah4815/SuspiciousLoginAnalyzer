import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# =========================================================
# GLOBAL STYLE (clean, report-ready)
# =========================================================
sns.set(style="whitegrid", context="talk")  # 'talk' = bigger fonts

# =========================================================
# 1. LOAD DATA
# =========================================================
df = pd.read_csv("data/rba-dataset-1000.csv")

# use Is Attack IP as the target — convert to string for seaborn countplots
df["Suspicious"] = df["Is Attack IP"].astype(str)   # "True"/"False"

print("\n=== Dataset Summary ===")
print(df.info())
print("\n=== Suspicious (Is Attack IP) counts ===")
print(df["Suspicious"].value_counts())
print()

total_rows = len(df)

# =========================================================
# 2. DISTRIBUTION: SUSPICIOUS vs NORMAL
# =========================================================
plt.figure(figsize=(8, 6))
ax = sns.countplot(
    x="Suspicious",
    data=df,
    hue="Suspicious",
    palette={"False": "#3498DB", "True": "#E74C3C"},
    legend=False
)

for p in ax.patches:
    height = p.get_height()
    pct = 100 * height / total_rows
    ax.text(
        p.get_x() + p.get_width() / 2.0,
        height + 5,
        f"{int(height)} ({pct:.1f}%)",
        ha="center",
        va="bottom",
        fontsize=12,
        weight="bold"
    )

ax.set_title("Distribution of Suspicious vs Normal Logins", fontsize=16, weight="bold")
ax.set_xlabel("Login Category", fontsize=14)
ax.set_ylabel("Number of Records", fontsize=14)
ax.set_xticklabels(["Normal Logins", "Suspicious Logins"])
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()

# =========================================================
# 3. LOGIN SUCCESS vs SUSPICIOUS
# =========================================================
plt.figure(figsize=(9, 6))
ax = sns.countplot(
    data=df,
    x="Login Successful",
    hue="Suspicious",
    palette={"False": "#3498DB", "True": "#E74C3C"}
)
ax.set_title("Login Outcome vs Suspicious Activity", fontsize=16, weight="bold")
ax.set_xlabel("Login Successful", fontsize=14)
ax.set_ylabel("Count", fontsize=14)
ax.set_xticklabels(["Failed (False)", "Successful (True)"])

for p in ax.patches:
    height = p.get_height()
    if height > 0:
        ax.text(
            p.get_x() + p.get_width() / 2.,
            height + 3,
            f"{int(height)}",
            ha="center",
            va="bottom",
            fontsize=11
        )

plt.legend(title="Suspicious", labels=["Normal", "Suspicious"])
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()

# =========================================================
# 4. TOP COUNTRIES / CITIES FOR SUSPICIOUS LOGINS
# =========================================================
suspicious_df = df[df["Suspicious"] == "True"]

if not suspicious_df.empty:
    # ---- countries ----
    top_countries = suspicious_df["Country"].value_counts().head(10)

    plt.figure(figsize=(10, 6))
    country_colors = sns.color_palette("Set2", len(top_countries))
    ax = sns.barplot(
        x=top_countries.values,
        y=top_countries.index,
        palette=country_colors
    )
    ax.set_title("Top 10 Countries with Suspicious Logins", fontsize=16, weight="bold")
    ax.set_xlabel("Count", fontsize=14)
    ax.set_ylabel("Country", fontsize=14)

    for i, v in enumerate(top_countries.values):
        ax.text(
            v + 0.5,
            i,
            str(v),
            va="center",
            fontsize=12,
            weight="bold"
        )

    plt.tight_layout()
    plt.show()

    # ---- cities ----
    top_cities = suspicious_df["City"].value_counts().head(10)

    plt.figure(figsize=(10, 6))
    city_colors = sns.color_palette("Paired", len(top_cities))
    ax = sns.barplot(
        x=top_cities.values,
        y=top_cities.index,
        palette=city_colors
    )
    ax.set_title("Top 10 Cities with Suspicious Logins", fontsize=16, weight="bold")
    ax.set_xlabel("Count", fontsize=14)
    ax.set_ylabel("City", fontsize=14)

    for i, v in enumerate(top_cities.values):
        ax.text(
            v + 0.5,
            i,
            str(v),
            va="center",
            fontsize=12,
            weight="bold"
        )

    plt.tight_layout()
    plt.show()
else:
    print("No suspicious rows to aggregate by Country/City.")

# =========================================================
# 5. ROUND-TRIP TIME COMPARISON
# =========================================================
if "Round-Trip Time [ms]" in df.columns:
    # keep a real boolean copy for this plot
    df["Suspicious_bool"] = df["Is Attack IP"]

    plt.figure(figsize=(8, 6))
    ax = sns.boxplot(
        data=df,
        x="Suspicious_bool",
        y="Round-Trip Time [ms]",
        palette={False: "#3498DB", True: "#E74C3C"}
    )
    ax.set_title("Round-Trip Time by Suspicious Activity", fontsize=16, weight="bold")
    ax.set_xlabel("Suspicious", fontsize=14)
    ax.set_ylabel("RTT (ms)", fontsize=14)
    ax.set_xticklabels(["Normal", "Suspicious"])
    plt.tight_layout()
    plt.show()
else:
    print("Column 'Round-Trip Time [ms]' not found — skipping RTT plot.")
