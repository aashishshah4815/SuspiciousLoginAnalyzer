# ml/features.py
from __future__ import annotations
from pathlib import Path
import pandas as pd

def _safe_read_csv(path: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()

def build_user_features(reports_dir: str | Path) -> pd.DataFrame:
    """
    Build one row per User with simple aggregate features from the PowerShell reports:
      - TotalEvents
      - DistinctComputers
      - TopPairEvents (max Events for any user-computer pair)
      - NumPairs (how many user-computer pairs made top list)
      - HotPairOver25k (indicator if any pair had >25k events)
    """
    rd = Path(reports_dir)
    users_dist   = _safe_read_csv(rd / "TopUsers_ByDistinctComputers.csv")
    users_events = _safe_read_csv(rd / "TopUsers_ByEvents.csv")
    pairs        = _safe_read_csv(rd / "TopUserComputerPairs.csv")

    if users_dist.empty and users_events.empty and pairs.empty:
        return pd.DataFrame()

    # base from users_events (has User, TotalEvents)
    base = pd.DataFrame()
    if not users_events.empty:
        base = users_events[["User", "TotalEvents"]].copy()
    elif not users_dist.empty:
        base = users_dist[["User", "DistinctComputers"]].copy()
        base["TotalEvents"] = 0
    else:
        # fall back to pairs to get unique users
        base = pd.DataFrame({"User": pairs["User"].unique()})
        base["TotalEvents"] = 0

    # add distinct computers
    if not users_dist.empty:
        base = base.merge(users_dist[["User", "DistinctComputers"]],
                          on="User", how="left")
    else:
        base["DistinctComputers"] = 0

    # add pair-based features
    if not pairs.empty:
        g = pairs.groupby("User", as_index=False)["Events"].agg(
            TopPairEvents="max", NumPairs="count"
        )
        base = base.merge(g, on="User", how="left")
    else:
        base["TopPairEvents"] = 0
        base["NumPairs"] = 0

    # simple indicator
    base["HotPairOver25k"] = (base["TopPairEvents"].fillna(0) > 25000).astype(int)

    # fill NaNs
    for col in ["TotalEvents", "DistinctComputers", "TopPairEvents", "NumPairs"]:
        if col in base.columns:
            base[col] = base[col].fillna(0)

    # ensure numeric
    for col in ["TotalEvents", "DistinctComputers", "TopPairEvents", "NumPairs"]:
        if col in base.columns:
            base[col] = pd.to_numeric(base[col], errors="coerce").fillna(0)

    return base

__all__ = ["build_user_features"]
