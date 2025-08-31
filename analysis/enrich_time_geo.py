# analysis/enrich_time_geo.py
from __future__ import annotations
import sys, math
from pathlib import Path
import pandas as pd
import numpy as np

"""
Input CSV must have at least:
 - User
 - Timestamp  (ISO or parseable; assumed UTC if no tz)
 - Country    (optional for geo)
 - Lat, Lon   (optional for geo)
"""

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    phi1 = math.radians(lat1); phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlmb/2)**2
    return 2*R*math.asin(math.sqrt(a))

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "Reports"
REPORTS.mkdir(exist_ok=True, parents=True)

inp = Path(sys.argv[1]) if len(sys.argv) > 1 else (REPORTS / "LoginEvents_Parsed.csv")
if not inp.exists():
    raise FileNotFoundError(f"Input not found: {inp}\nPass a CSV with columns: User, Timestamp[, Country, Lat, Lon]")

df = pd.read_csv(inp)
if "User" not in df.columns or "Timestamp" not in df.columns:
    raise ValueError("CSV must include at least: User, Timestamp")

df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce", utc=True)
df = df.dropna(subset=["Timestamp"]).sort_values(["User","Timestamp"])
df["Hour"] = df["Timestamp"].dt.hour

# Time-of-day Z: per-user frequency by hour
hour_counts = df.groupby(["User","Hour"]).size().rename("Count").reset_index()
# For each user, compute z-score of the hour buckets
hour_stats = hour_counts.groupby("User")["Count"].agg(["mean","std"]).reset_index()
hour_counts = hour_counts.merge(hour_stats, on="User", how="left")
hour_counts["HourZ"] = (hour_counts["Count"] - hour_counts["mean"]) / (hour_counts["std"].replace(0, np.nan))
hour_counts["HourZ"] = hour_counts["HourZ"].fillna(0)

df = df.merge(hour_counts[["User","Hour","HourZ"]], on=["User","Hour"], how="left")

# Impossible travel: per-user consecutive events
if {"Lat","Lon"}.issubset(df.columns):
    df["SpeedKmh"] = np.nan
    def calc_speed(g):
        g = g.sort_values("Timestamp").copy()
        g["Lat_prev"] = g["Lat"].shift(1)
        g["Lon_prev"] = g["Lon"].shift(1)
        g["ts_prev"]  = g["Timestamp"].shift(1)
        mask = g[["Lat","Lon","Lat_prev","Lon_prev","ts_prev"]].notna().all(axis=1)
        dists = []
        speeds = []
        for i, row in g[mask].iterrows():
            d = haversine_km(row["Lat_prev"], row["Lon_prev"], row["Lat"], row["Lon"])
            dt_h = (row["Timestamp"] - row["ts_prev"]).total_seconds() / 3600.0
            v = d / dt_h if dt_h > 0 else np.inf
            dists.append((i, v))
        g.loc[[i for i,_ in dists], "SpeedKmh"] = [v for _,v in dists]
        return g
    df = df.groupby("User", group_keys=False).apply(calc_speed)
    # Flag > 900 km/h (commercial aircraft range) within short intervals
    df["GeoJumpFlag"] = (df["SpeedKmh"] > 900).fillna(False)
else:
    df["SpeedKmh"] = np.nan
    df["GeoJumpFlag"] = False

out = REPORTS / "TimeGeo_Anomalies.csv"
df[["User","Timestamp","Country","Lat","Lon","Hour","HourZ","SpeedKmh","GeoJumpFlag"] \
   if "Country" in df.columns else ["User","Timestamp","Hour","HourZ","SpeedKmh","GeoJumpFlag"]].to_csv(out, index=False)
print("Wrote:", out)
