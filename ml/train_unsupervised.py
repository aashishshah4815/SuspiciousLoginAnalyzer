# ml/train_unsupervised.py
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM


def load_reports(report_dir: Path) -> pd.DataFrame:
    """
    Build a per-user feature table from your existing reports.
    Uses:
      - TopUsers_ByEvents.csv  -> TotalEvents
      - TopUsers_ByDistinctComputers.csv -> DistinctComputers
    Falls back gracefully if one file is missing.
    """
    feats = {}

    # By events
    f_events = report_dir / "TopUsers_ByEvents.csv"
    if f_events.exists():
        df = pd.read_csv(f_events)
        if {"User", "TotalEvents"}.issubset(df.columns):
            for _, r in df.iterrows():
                u = str(r["User"])
                feats.setdefault(u, {})
                feats[u]["TotalEvents"] = float(r["TotalEvents"])

    # By distinct computers
    f_distinct = report_dir / "TopUsers_ByDistinctComputers.csv"
    if f_distinct.exists():
        df = pd.read_csv(f_distinct)
        if {"User", "DistinctComputers"}.issubset(df.columns):
            for _, r in df.iterrows():
                u = str(r["User"])
                feats.setdefault(u, {})
                feats[u]["DistinctComputers"] = float(r["DistinctComputers"])

    if not feats:
        raise FileNotFoundError(
            "No usable feature sources found in Reports/. "
            "Expected TopUsers_ByEvents.csv and/or TopUsers_ByDistinctComputers.csv."
        )

    # Build the frame
    rows = []
    for user, v in feats.items():
        rows.append(
            {
                "User": user,
                "TotalEvents": float(v.get("TotalEvents", 0.0)),
                "DistinctComputers": float(v.get("DistinctComputers", 0.0)),
            }
        )
    df_feats = pd.DataFrame(rows).sort_values("User").reset_index(drop=True)
    return df_feats


def train_models(df_feats: pd.DataFrame, random_state: int = 42):
    feature_cols = ["TotalEvents", "DistinctComputers"]

    X = df_feats[feature_cols].fillna(0.0).to_numpy(dtype=float)

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # Isolation Forest (robust default)
    iforest = IsolationForest(
        n_estimators=300,
        contamination="auto",  # lets model infer a rough proportion
        random_state=random_state,
    )
    iforest.fit(Xs)
    if_scores = -iforest.score_samples(Xs)  # higher = more anomalous

    # One-Class SVM (alternative view)
    ocsvm = OneClassSVM(gamma="scale", nu=0.05)  # nu ~ expected outlier fraction
    ocsvm.fit(Xs)
    svm_scores = -ocsvm.score_samples(Xs)

    # Normalize scores to [0,1] for readability
    def norm(a):
        a = np.asarray(a, float)
        lo, hi = np.nanmin(a), np.nanmax(a)
        if hi <= lo:
            return np.zeros_like(a)
        return (a - lo) / (hi - lo)

    out = df_feats[["User"]].copy()
    out["IForestScore"] = norm(if_scores)
    out["OCSVMScore"] = norm(svm_scores)
    out["EnsembleScore"] = norm(0.5 * (out["IForestScore"] + out["OCSVMScore"]))

    artifacts = {
        "scaler": scaler,
        "iforest": iforest,
        "ocsvm": ocsvm,
        "feature_cols": feature_cols,
    }
    return out, artifacts


def main():
    ap = argparse.ArgumentParser(description="Train unsupervised anomaly models from Reports/")
    ap.add_argument("--reports", type=str, default="Reports", help="Path to the Reports folder")
    ap.add_argument("--outdir", type=str, default="models", help="Where to save models/results")
    args = ap.parse_args()

    report_dir = Path(args.reports).resolve()
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Loading reports from: {report_dir}")
    df_feats = load_reports(report_dir)
    print(f"    Users in feature table: {len(df_feats):,}")

    print("[*] Training IsolationForest + OneClassSVM...")
    scores, artifacts = train_models(df_feats)

    # Save scores for the dashboard or ad-hoc review
    scores_path = outdir / "AnomalyScores.csv"
    scores.sort_values("EnsembleScore", ascending=False).to_csv(scores_path, index=False)
    print(f"[+] Wrote scores -> {scores_path}")

    # Persist models & metadata
    joblib.dump(artifacts["scaler"], outdir / "scaler.joblib")
    joblib.dump(artifacts["iforest"], outdir / "iforest.joblib")
    joblib.dump(artifacts["ocsvm"], outdir / "ocsvm.joblib")
    (outdir / "feature_columns.json").write_text(json.dumps(artifacts["feature_cols"]))
    print(f"[+] Saved model artifacts to: {outdir}")

    # Quick CLI preview
    print("\nTop 10 most anomalous (by EnsembleScore):")
    print(scores.sort_values("EnsembleScore", ascending=False).head(10).to_string(index=False))


if __name__ == "__main__":
    main()
