import pandas as pd

# 1. load data
df = pd.read_csv("data/rba-dataset-1000.csv")

# 2. basic info
print("\n=== DATA INFO ===")
print(df.info())

print("\n=== FIRST 5 ROWS ===")
print(df.head())

# 3. check target-like columns
print("\n=== Login Successful counts ===")
print(df["Login Successful"].value_counts(dropna=False))

print("\n=== Is Attack IP counts ===")
print(df["Is Attack IP"].value_counts(dropna=False))

print("\n=== Is Account Takeover counts ===")
print(df["Is Account Takeover"].value_counts(dropna=False))
