\# 📄 Features Documentation — Suspicious Login Pattern Analyzer



This document describes all engineered features used for anomaly detection in login events.  

Features are extracted from normalized authentication logs (`LoginEvents\_Parsed.csv`) and enriched with geo/time information.



---



\## 1. TotalEvents

\- \*\*Definition:\*\* Total number of login events for a given user.  

\- \*\*Formula:\*\*  

&nbsp; \\\[

&nbsp; \\text{TotalEvents}(u) = \\sum\_{i=1}^{N} 1 \\quad \\forall \\text{ events by user } u

&nbsp; \\]

\- \*\*Source:\*\* LANL authentication logs.  

\- \*\*Use:\*\* High volume of logins may indicate automated activity.



---



\## 2. DistinctHosts

\- \*\*Definition:\*\* Number of unique computers a user logged into.  

\- \*\*Formula:\*\*  

&nbsp; \\\[

&nbsp; \\text{DistinctHosts}(u) = |\\{ h \\mid (u,h) \\in \\text{logins} \\}|

&nbsp; \\]

\- \*\*Source:\*\* LANL authentication logs.  

\- \*\*Use:\*\* Helps detect users moving across unusually many machines.



---



\## 3. GeoJumpFlag

\- \*\*Definition:\*\* Flags if a user’s consecutive logins imply impossible travel speed.  

\- \*\*Formula:\*\*  

&nbsp; - Compute distance between (lat₁, lon₁) and (lat₂, lon₂).  

&nbsp; - Compute time difference Δt.  

&nbsp; - Speed = Distance ÷ Δt.  

&nbsp; - Flag = 1 if Speed > \*\*900 km/h\*\*, else 0.  

\- \*\*Source:\*\* IP geolocation (GeoLite2).  

\- \*\*Use:\*\* Detects suspicious location jumps.



---



\## 4. HourZ

\- \*\*Definition:\*\* Z-score anomaly of login hour compared to user’s baseline.  

\- \*\*Formula:\*\*  

&nbsp; \\\[

&nbsp; Z = \\frac{h\_i - \\mu\_u}{\\sigma\_u}

&nbsp; \\]

&nbsp; where \\( h\_i \\) = login hour, \\( \\mu\_u \\) = mean login hour, \\( \\sigma\_u \\) = std deviation.  

\- \*\*Source:\*\* Timestamp field.  

\- \*\*Use:\*\* Detects logins at unusual times for a user.



---



\## 5. FailedRatio

\- \*\*Definition:\*\* Ratio of failed logins to total attempts.  

\- \*\*Formula:\*\*  

&nbsp; \\\[

&nbsp; \\text{FailedRatio}(u) = \\frac{\\text{FailedEvents}(u)}{\\text{TotalEvents}(u)}

&nbsp; \\]

\- \*\*Source:\*\* Authentication logs (success/failure flag).  

\- \*\*Use:\*\* Many failed logins may suggest brute-force attempts.



---



\## 6. EventTypeDiversity

\- \*\*Definition:\*\* Number of distinct logon event types per user (e.g., interactive, network, batch).  

\- \*\*Formula:\*\*  

&nbsp; \\\[

&nbsp; \\text{EventTypeDiversity}(u) = |\\{ t \\mid (u,t) \\in \\text{logins} \\}|

&nbsp; \\]

\- \*\*Source:\*\* Event logs.  

\- \*\*Use:\*\* Abnormal diversity may indicate unusual access patterns.



---



\## 7. SessionDuration

\- \*\*Definition:\*\* Average session duration for a user.  

\- \*\*Formula:\*\*  

&nbsp; \\\[

&nbsp; \\text{SessionDuration}(u) = \\frac{1}{N}\\sum\_{i=1}^{N} (t\_{\\text{logout}} - t\_{\\text{login}})

&nbsp; \\]

\- \*\*Source:\*\* Authentication logs with login/logout pairs.  

\- \*\*Use:\*\* Very short or very long sessions may signal misuse.



---



\## 8. LateralMovement

\- \*\*Definition:\*\* Rare transitions between computers (src → dst) in login graph.  

\- \*\*Formula:\*\*  

&nbsp; - Build directed graph: edges = (src\_computer → dst\_computer).  

&nbsp; - Compute edge frequency.  

&nbsp; - Flag edges below threshold (e.g., < 1%).  

\- \*\*Source:\*\* LANL authentication logs.  

\- \*\*Use:\*\* Detects unusual cross-machine logins that may represent attacker movement.



---



\## 📌 Notes

\- Features are combined into a user-level feature vector by `ml/features.py`.  

\- These features are used in both \*\*unsupervised models\*\* (Isolation Forest, One-Class SVM) and \*\*supervised models\*\* (Random Forest).  

\- All engineered features are written to `Reports/` as CSVs for model training and dashboard visualization.



