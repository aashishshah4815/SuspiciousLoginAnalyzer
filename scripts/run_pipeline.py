import pandas as pd
import os

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "rba-dataset-1000.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "output", "processed_rba_dataset.csv")

print("📁 Base Directory:", BASE_DIR)
print("📄 Loading:", DATA_PATH)

def preprocess(df):
    df = df.copy()
    if "Login Timestamp" in df.columns:
        df["Login Timestamp"] = pd.to_datetime(df["Login Timestamp"], errors="coerce")
    for col in ["Login Successful", "Is Attack IP", "Is Account Takeover"]:
        if col in df.columns:
            df[col] = df[col].astype(bool)
    for col in ["Country", "Region", "City"]:
        if col in df.columns:
            df[col] = df[col].fillna("Unknown")
    if "Device Type" in df.columns:
        df["Device Type"] = df["Device Type"].astype(str).str.lower().str.strip()
    return df

def detect_suspicious(df):
    df = df.copy()
    df["rule_failed_login"] = ~df["Login Successful"]
    df["rule_attack_ip"] = df["Is Attack IP"]
    df["rule_account_takeover"] = df["Is Account Takeover"]
    top_countries = set(df["Country"].value_counts().head(5).index)
    df["rule_unusual_country"] = ~df["Country"].isin(top_countries)
    df["Suspicious"] = (
        df["rule_failed_login"]
        | df["rule_attack_ip"]
        | df["rule_account_takeover"]
    )
    return df

def report(df):
    total = len(df)
    sus = df["Suspicious"].sum()
    print(f"✅ Total logins: {total}")
    print(f"🚨 Suspicious logins: {sus} ({(sus/total)*100:.2f}%)")
    print("\nTop suspicious countries:")
    print(df[df["Suspicious"]]["Country"].value_counts().head(10))

def main():
    df = pd.read_csv(DATA_PATH)
    df = preprocess(df)
    df = detect_suspicious(df)
    report(df)
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)
    print("\n💾 Processed dataset saved to:", OUTPUT_PATH)

if __name__ == "__main__":
    main()
