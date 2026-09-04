# Context-Aware Alert Prioritization in Wazuh SIEM Using Hybrid Risk Scoring and Machine Learning

## 1. Introduction

Security Information and Event Management (SIEM) systems are widely used in modern Security Operations Centers (SOCs) to collect, correlate, and analyze security events, but large alert volumes can overwhelm analysts and delay the investigation of high-risk incidents [14]. A major limitation is that alerts are often ranked mainly by static rule severity or identifiers, which may not reflect the real operational risk of an event when factors such as asset criticality, user behavior, vulnerability exposure, timing, and surrounding attack patterns are considered. Prior research has therefore explored context-aware alert classification, adaptive SIEM correlation, contextual log filtering, reinforcement learning-based prioritization, and explainable graph-based triage to reduce alert fatigue and help analysts focus on alerts with greater security impact [1], [5], [6], [7], [8].

Wazuh provides a suitable base for this type of research because it already supports log analysis, endpoint monitoring, rule-based detection, vulnerability detection, threat intelligence integration, MITRE ATT&CK-aligned evaluation, and active response workflows. Recent Wazuh-focused studies have explored real-time threat feed integration [3], MITRE ATT&CK evaluation [12], and machine learning-based improvements to threat detection [13]. However, many of these approaches focus mainly on detection accuracy, threat intelligence enrichment, or response automation. Less attention has been given to an additional Wazuh-based prioritization layer that uses created context to decide which alerts should be investigated first.

This project proposes a context-aware alert prioritization framework built on top of Wazuh. The goal is not to replace Wazuh's existing detection rules or build a new SIEM platform, but to design an additional prioritization layer that enriches Wazuh alerts with operational and security context. The proposed framework will use alert and log information to create context such as the likely target of attack, possible blast radius, estimated attacker sophistication, duration of attack, unusual event timing, recent attack patterns, alert frequency, asset criticality, vulnerability exposure, threat intelligence reputation, MITRE ATT&CK tactic, and historical alert behavior. This context will then be used to support a hybrid risk scoring model that combines Wazuh rule severity with contextual risk factors to produce an interpretable priority score for SOC analysts. Related risk-based prioritization work in SIEM environments supports the need for transparent scoring models that remain understandable to human analysts [9], while broader SIEM alert management research shows the value of combining multiple alert features during prioritization [10].

In addition to hybrid scoring, this project explores graph-based context link analysis. Alerts and related entities can be represented as an alert graph, where nodes represent alerts, assets, users, vulnerabilities, attack techniques, threat indicators, or other relevant entities, and edges represent contextual links created from the extracted context. A graph neural network can then be applied over this alert graph so that risk is propagated through connected alerts and entities. This allows low-severity alerts linked to high-risk neighbours to be promoted when they are part of a wider suspicious pattern. This direction follows recent Wazuh graph-based research on real-time attack path prediction using event correlation [4] and Wazuh EDR telemetry research that applies graph neural networks to model relationships among security-relevant events and endpoint behaviors [11].

The expected contribution of this work is a Wazuh-based context-aware alert prioritization framework that supports SOC triage by reducing repeated low-value alerts and promoting high-risk alerts that may otherwise be hidden in large alert volumes. The project contributes a practical context creation method for transforming Wazuh alerts and related logs into useful prioritization features, a hybrid risk scoring model that remains interpretable for analysts, and a graph-based link analysis approach for associating related alerts into broader incidents. The framework will be evaluated by comparing Wazuh's default severity-based ranking against the proposed context-aware ranking, with possible use of MITRE ATT&CK-aligned attack simulations to assess whether the system improves the visibility of high-risk security events [12].

## 2. Project Scope

The scope of this project includes the following key areas:

- Wazuh-Based Alert Prioritization: Designing an additional prioritization layer on top of Wazuh, rather than replacing Wazuh's existing detection rules or building a new SIEM platform.

- Contextual Alert Enrichment: Enhancing Wazuh alerts with contextual information such as rule level, MITRE ATT&CK tactic, alert frequency, asset criticality, vulnerability exposure, threat intelligence reputation, and historical alert behavior.

- Hybrid Risk Scoring: Combining transparent rule-based context scoring with a lightweight machine learning component to rank alerts according to both technical severity and operational importance.

- Simple Machine Learning Integration: Applying practical machine learning methods such as Random Forest, DBSCAN, or Isolation Forest to support alert classification, anomaly recognition, or repeated-alert noise reduction.

- Analyst-Focused Output: Producing a prioritized alert list that supports SOC triage and helps reduce analyst workload caused by repeated or low-value alerts.

- Limited Initial Automation: Keeping advanced functions such as graph neural networks, reinforcement learning, LLM-based triage, and fully automated SOC response outside the initial project scope, while leaving them as possible future extensions.

## 3. Proposed Contributions

This work makes the following key contributions:

1. Context-Aware Wazuh Alert Prioritization Framework: A hybrid framework that enriches Wazuh alerts with operational context such as MITRE ATT&CK mapping, asset criticality, vulnerability exposure, threat intelligence, alert frequency, and historical behavior.

2. Hybrid Risk Scoring Model: A transparent scoring method that combines Wazuh rule severity with contextual risk factors to produce an interpretable priority score for SOC analysts.

3. Simple Machine Learning Component: Integration of lightweight machine learning methods, such as Random Forest, DBSCAN, or Isolation Forest, to support alert classification, anomaly recognition, or repeated-alert noise reduction.

4. Alert Fatigue Reduction: A prioritization mechanism designed to reduce repeated low-value alerts and promote high-risk alerts that may otherwise be hidden in large alert volumes.

5. Wazuh-Based Evaluation: An evaluation approach comparing default Wazuh severity ranking against the proposed context-aware ranking, with possible use of MITRE ATT&CK-aligned attack simulations.

## 4. Candidate Machine Learning Direction

For Deliverable 1, the most practical machine learning component is a simple alert pattern recognition module:

- Random Forest can classify alerts into priority classes using labeled or simulated alert data.
- DBSCAN can group repeated or similar alerts to identify noisy alert clusters.
- Isolation Forest can detect unusual alert patterns without requiring many labels.

The recommended starting point is Random Forest if labeled data can be produced from attack simulations, or Isolation Forest/DBSCAN if the available dataset is mostly unlabeled.

