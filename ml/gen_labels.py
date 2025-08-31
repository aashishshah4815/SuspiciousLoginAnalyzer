import pandas as pd
from pathlib import Path

REPORTS = Path("Reports")
LABELS = REPORTS / "labels.csv"

def main():
    # Load summary of users (from Analyzer outputs)
    try:
        df = pd.read_csv(REPORTS / "TopUsers_ByEvents.csv")
    except FileNotFoundError:
        raise SystemExit("Run Analyzer.ps1 first to generate Reports.")

    # Extract just User column
    users = df["User"].dropna().unique()

    # Example labeling rule:
    # - Flag a few high-volume users as suspicious (1)
    # - Others default to normal (0)
    labels = []
    for u in users:
        if str(u) in ["U12", "U4075", "U4258"]:  # suspicious from unsupervised
            labels.append((u, 1))
        else:
            labels.append((u, 0))

    out = pd.DataFrame(labels, columns=["User","label"])
    out.to_csv(LABELS, index=False)
    print(f"[+] Wrote labels file with {len(out)} users -> {LABELS}")

if __name__ == "__main__":
    main()
