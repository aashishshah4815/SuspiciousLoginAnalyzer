# enrich_geo.py
import pandas as pd
import geoip2.database

db_path = "GeoLite2-City.mmdb"   # download from MaxMind
inp = "Reports/SuspiciousFindings.csv"
out = "Reports/SuspiciousFindings_Enriched.csv"

df = pd.read_csv(inp)
reader = geoip2.database.Reader(db_path)

def lookup(ip):
    try:
        resp = reader.city(str(ip))
        return resp.country.name, resp.location.latitude, resp.location.longitude
    except:
        return "Unknown", None, None

if "IP" in df.columns:
    df[["Country","Lat","Lon"]] = df["IP"].apply(
        lambda ip: pd.Series(lookup(ip))
    )

df.to_csv(out, index=False)
print(f"[+] Wrote {out}")
