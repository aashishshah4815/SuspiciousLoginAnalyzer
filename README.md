# \# 🔐 Suspicious Login Pattern Analyzer

# 

# \*\*GitHub Repo (datasets):\*\* \[Real-CyberSecurity-Datasets](https://github.com/gfek/Real-CyberSecurity-Datasets)  

# \*\*Project Repo:\*\* `aashishshah4815/SuspiciousLoginAnalyzer`

# 

# This project uncovers anomalous login behaviors by applying machine learning on enterprise authentication logs.  

# It combines \*\*data aggregation\*\*, \*\*feature engineering\*\*, \*\*unsupervised \& supervised models\*\*, and an \*\*interactive Streamlit dashboard\*\*.

# 

# ---

# 

# \## 🚀 Project Workflow

# 

# ```mermaid

# flowchart LR

# &nbsp;   A\[Raw Datasets (LANL, Windows, CloudTrail, Intrusion)] --> B\[Normalization → LoginEvents\_Parsed.csv]

# &nbsp;   B --> C\[Feature Engineering]

# &nbsp;   C --> D\[Unsupervised ML (IForest + OCSVM)]

# &nbsp;   C --> E\[Supervised ML (Random Forest)]

# &nbsp;   D --> F\[Reports/AnomalyScores.csv]

# &nbsp;   E --> G\[Reports/ML\_Findings\_Supervised.csv]

# &nbsp;   C --> H\[TimeGeo Anomalies]

# &nbsp;   F --> I\[Streamlit App]

# &nbsp;   G --> I

# &nbsp;   H --> I



