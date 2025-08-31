# analysis/convert_to_login_events.py
from pathlib import Path
import pandas as pd
import sys

"""
Convert LANL-style authentication logs into a normalized LoginEvents_Parsed.csv

Input requirements:
 - CSV must include columns: time, src_user, dst_computer (at least)
 - Optional: if IP/geo fields exist, they will be carried over
"""

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "Reports"
REPORTS.mkdir(exist_ok=True, parents=True)

# Input path
inp = Path(sys.argv[1]) if len(sys.argv) > 1 else (REPORTS / "lanl_auth.csv")
if not inp.exists():
    raise FileNotFoundError(f"Input not found: {inp}")

df = pd.read_csv(inp)

# Validate
needed = {"time","src_user","dst_computer"}
if not needed.issubset(df.columns):
    raise ValueError(f"CSV must include at least columns: {needed}")

# Normalize timestamp
df["Timestamp"] = pd.to_datetime(df["time"], errors="coerce", utc=True)

# Pick main user
df["User"] = df["src_user"].astype(str)

# Pick computer
df["Computer"] = df["dst_computer"].astype(str)

# If geo fields exist, pass them through; else fill blank
geo_cols = []
for c in ["Country","Lat","Lon"]:
    if c in df.columns:
        geo_cols.append(c)
    else:
        df[c] = None
        geo_cols.append(c)

out_cols = ["User","Timestamp","Computer"] + geo_cols
out_df = df[out_cols].dropna(subset=["Timestamp"])

out_path = REPORTS / "LoginEvents_Parsed.csv"
out_df.to_csv(out_path, index=False)
print(f"[+] Wrote {out_path} with {len(out_df):,} rows")
