# ml_model.py — Suspicious Login Classifier (Advanced)
# Project: SuspiciousLoginAnalyzer
# Author: Aashish (TAFE)

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)
from sklearn.ensemble import RandomForestClassifier
import joblib

# =========================================================
# 0. CONFIG / PATHS
# =========================================================
DATA_PATH = "data/rba-dataset-1000.csv"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# =========================================================
# 1. LOAD DATA
# =========================================================
df = pd.read_csv(DATA_PATH)

# Target: use Is Attack IP (you confirmed this one has 66 True)
TARGET_COL = "Is Attack IP"

# Optional: keep a copy
df_original = df.copy()

print("\n=== DATA HEAD ===")
print(df.head())

# =========================================================
# 2. BASIC CLEANUP
# =========================================================
# Drop columns that are pure identifiers or unhelpful
# (you can tune this based on your assignment)
cols_to_drop = ["index"]  # you had an 'index' column in the CSV
for c in cols_to_drop:
    if c in df.columns:
        df = df.drop(columns=[c])

# Convert timestamp to datetime + extract hour (useful feature)
if "Login Timestamp" in df.columns:
    df["Login Timestamp"] = pd.to_datetime(df["Login Timestamp"])
    df["login_hour"] = df["Login Timestamp"].dt.hour
    # we can drop full timestamp to avoid high cardinality
    df = df.drop(columns=["Login Timestamp"])

# =========================================================
# 3. FEATURE / TARGET SPLIT
# =========================================================
X = df.drop(columns=[TARGET_COL])
y = df[TARGET_COL].astype(int)  # True/False -> 1/0

# Identify column types
numeric_features = []
categorical_features = []

for col in X.columns:
    if pd.api.types.is_numeric_dtype(X[col]):
        numeric_features.append(col)
    else:
        categorical_features.append(col)

print("\nNumeric features:", numeric_features)
print("Categorical features:", categorical_features)

# =========================================================
# 4. PREPROCESSOR
# =========================================================
numeric_transformer = "passthrough"

categorical_transformer = OneHotEncoder(
    handle_unknown="ignore",
    sparse_output=False  # sklearn >=1.2 uses sparse_output
)

preprocessor = ColumnTransformer(
    transformers=[
        ("num", numeric_transformer, numeric_features),
        ("cat", categorical_transformer, categorical_features),
    ]
)

# =========================================================
# 5. MODEL
# =========================================================
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",   # helps a bit with 66 vs 934 imbalance
    n_jobs=-1
)

# Full pipeline
clf = Pipeline(
    steps=[
        ("preprocess", preprocessor),
        ("clf", model)
    ]
)

# =========================================================
# 6. TRAIN / TEST SPLIT
# =========================================================
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.25,
    random_state=42,
    stratify=y   # keep imbalance same in train/test
)

print(f"\nTrain size: {X_train.shape}, Test size: {X_test.shape}")

# =========================================================
# 7. TRAIN
# =========================================================
clf.fit(X_train, y_train)
print("\n✅ Model training complete.")

# =========================================================
# 8. EVALUATE
# =========================================================
y_pred = clf.predict(X_test)
y_proba = clf.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)

print("\n=== EVALUATION METRICS ===")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1-score : {f1:.4f}")

print("\n=== CLASSIFICATION REPORT ===")
print(classification_report(y_test, y_pred, digits=4))

# =========================================================
# 9. CONFUSION MATRIX (PLOT)
# =========================================================
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(5, 4))
sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=["Normal", "Suspicious"],
    yticklabels=["Normal", "Suspicious"]
)
plt.title("Confusion Matrix — Suspicious Login Classifier")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.show()

# =========================================================
# 10. FEATURE IMPORTANCE (AFTER OHE)
# =========================================================
# We only get feature importances from the *fitted* RandomForest, not the pipeline,
# so we have to reconstruct the feature names from the preprocessor.

# 1) get one-hot encoder from pipeline
ohe = clf.named_steps["preprocess"].named_transformers_["cat"]
# 2) get feature names
ohe_feature_names = ohe.get_feature_names_out(categorical_features)
all_feature_names = numeric_features + list(ohe_feature_names)

# 3) get importances from RF
rf_model = clf.named_steps["clf"]
importances = rf_model.feature_importances_

# 4) build DataFrame
fi_df = pd.DataFrame({
    "feature": all_feature_names,
    "importance": importances
}).sort_values(by="importance", ascending=False)

print("\n=== TOP 20 FEATURE IMPORTANCES ===")
print(fi_df.head(20))

# 5) plot top 15
top_n = 15
plt.figure(figsize=(10, 6))
sns.barplot(
    data=fi_df.head(top_n),
    x="importance",
    y="feature",
    palette="viridis"
)
plt.title("Top Feature Importances (Random Forest)", fontsize=16, weight="bold")
plt.xlabel("Importance")
plt.ylabel("Feature")
plt.tight_layout()
plt.show()

# =========================================================
# 11. SAVE MODEL
# =========================================================
model_path = os.path.join(MODEL_DIR, "suspicious_login_rf.pkl")
joblib.dump(clf, model_path)
print(f"\n✅ Model saved to: {model_path}")
