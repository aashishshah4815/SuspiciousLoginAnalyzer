# ml/train_supervised.py
from __future__ import annotations
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, f1_score
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler

from ml.features import build_user_features

LABELS = "Reports/labels.csv"
OUT    = "Reports/ML_Findings_Supervised.csv"

def main() -> None:
    feats = build_user_features("Reports")
    if feats.empty:
        sys.exit("No features found. Run Analyzer.ps1 first to generate Reports/*.csv")

    # Load labels
    try:
        labels = pd.read_csv(LABELS)
    except Exception as e:
        sys.exit(f"Missing or unreadable labels file: {LABELS} ({e})")

    if not {"User", "label"}.issubset(labels.columns):
        sys.exit("labels.csv must contain columns: User,label")

    # Join features + labels on User
    df = feats.merge(labels, on="User", how="inner")
    if df.empty:
        sys.exit("No overlap between features and labels on 'User'.")

    # Build X / y
    X_cols = [c for c in df.columns if c not in ("User", "label")]
    X = df[X_cols].to_numpy()
    y = df["label"].to_numpy().astype(int)

    # Show class distribution
    unique, counts = np.unique(y, return_counts=True)
    dist = dict(zip(unique.tolist(), counts.tolist()))
    print("Label distribution:", dist)

    # Decide how to split
    can_stratify = (len(unique) == 2 and min(counts) >= 2)
    test_size = 0.3 if len(y) >= 4 else 0.5  # small sets: leave some for test

    if len(y) < 3:
        print("[!] Very few labeled samples; training on ALL labeled data and skipping test metrics.")
        Xtr, ytr = X, y
        Xte, yte = None, None
    else:
        Xtr, Xte, ytr, yte = train_test_split(
            X, y,
            test_size=test_size,
            random_state=42,
            stratify=y if can_stratify else None,
            shuffle=True,
        )
        if not can_stratify:
            print("[!] Falling back to NON-stratified split because a class has < 2 samples.")

    # Scale + train
    scaler = StandardScaler()
    Xtr = scaler.fit_transform(Xtr)
    clf = RandomForestClassifier(
        n_estimators=400,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    clf.fit(Xtr, ytr)

    # Report (if we have a test set)
    if Xte is not None:
        Xte = scaler.transform(Xte)
        proba = clf.predict_proba(Xte)[:, 1]
        preds = (proba >= 0.5).astype(int)
        print("\n[Hold-out Test Set Results]")
        print(classification_report(yte, preds, digits=4))
        try:
            print("ROC-AUC:", roc_auc_score(yte, proba))
        except Exception:
            print("ROC-AUC: n/a (only one class present in y_true or other issue)")

    # --- Cross-Validation ---
    if len(y) >= 5 and len(np.unique(y)) > 1:
        print("\n[5-Fold Stratified CV Results]")
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        f1_scores = cross_val_score(clf, scaler.fit_transform(X), y, cv=cv, scoring="f1")
        print("F1 scores per fold:", f1_scores)
        print(f"Mean F1: {np.mean(f1_scores):.3f} ± {np.std(f1_scores):.3f}")
    else:
        print("[!] Not enough samples for cross-validation.")

    # Score ALL users (from feats)
    Xall = scaler.transform(feats[X_cols].to_numpy())
    all_proba = clf.predict_proba(Xall)[:, 1]
    out = feats[["User"]].copy()
    out["Sup_ProbBad"] = all_proba

    Path(OUT).write_text(out.to_csv(index=False), encoding="utf-8")
    print(f"[+] Wrote {OUT}")

    # --- Feature importances ---
    try:
        fi = getattr(clf, "feature_importances_", None)
        if fi is not None:
            imp = pd.DataFrame({"feature": X_cols, "importance": fi})
            imp.sort_values("importance", ascending=False).to_csv("Reports/feature_importances.csv", index=False)
            print("[+] Wrote Reports/feature_importances.csv")
    except Exception as e:
        print("[!] Skipped feature_importances:", e)

if __name__ == "__main__":
    main()
