# analysis/evaluate_supervised.py
from pathlib import Path
import json
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    average_precision_score,
    precision_recall_curve,
    confusion_matrix,
)
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "Reports"
REPORTS.mkdir(exist_ok=True, parents=True)

preds_path = REPORTS / "ML_Findings_Supervised.csv"
labels_path = REPORTS / "labels.csv"

if not preds_path.exists():
    raise FileNotFoundError(f"Missing {preds_path}")
if not labels_path.exists():
    raise FileNotFoundError(f"Missing {labels_path}")

preds = pd.read_csv(preds_path)
labels = pd.read_csv(labels_path)

df = preds.merge(labels, on="User", how="inner")
y_true = df["label"].astype(int).values

# Pick probability column
prob_col = None
for c in ["Sup_ProbBad", "prob", "score", "Score"]:
    if c in df.columns:
        prob_col = c
        break
if prob_col is None:
    raise ValueError("Could not find probability column in supervised CSV")

y_score = df[prob_col].astype(float).values
y_pred = (y_score >= 0.5).astype(int)

# Metrics
ap = average_precision_score(y_true, y_score)
roc = roc_auc_score(y_true, y_score) if len(np.unique(y_true)) > 1 else float("nan")
report_txt = classification_report(y_true, y_pred, digits=4, zero_division=0)
cm = confusion_matrix(y_true, y_pred)

# PR curve
prec, rec, _ = precision_recall_curve(y_true, y_score)
plt.figure()
plt.plot(rec, prec, label=f"AP={ap:.3f}")
plt.xlabel("Recall")
plt.ylabel("Precision")
plt.title("Precision–Recall Curve")
plt.legend()
plt.grid(True, alpha=0.3)
plt.savefig(REPORTS / "PR_curve.png", dpi=150)
plt.close()

# Confusion matrix
plt.figure()
plt.imshow(cm, cmap="Blues")
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
for (i, j), v in np.ndenumerate(cm):
    plt.text(j, i, str(v), ha="center", va="center")
plt.colorbar()
plt.savefig(REPORTS / "confusion_matrix.png", dpi=150)
plt.close()

# Save metrics
metrics = {
    "samples": int(len(df)),
    "positives": int(y_true.sum()),
    "ap": float(ap),
    "roc_auc": float(roc),
    "classification_report": report_txt,
}
(Path(REPORTS / "metrics.json")).write_text(json.dumps(metrics, indent=2))
(Path(REPORTS / "results.md")).write_text(
    "# Supervised Evaluation\n\n"
    f"- Samples: {metrics['samples']}\n"
    f"- Positives: {metrics['positives']}\n"
    f"- Average Precision (AP): {ap:.3f}\n"
    f"- ROC-AUC: {roc:.3f}\n\n"
    "## Classification Report\n\n"
    "```\n" + report_txt + "\n```\n"
)

print("Wrote Reports/metrics.json, results.md, PR_curve.png, confusion_matrix.png")
