# Literature grouping for Wazuh-focused context-aware SIEM

This is a working grouping of the papers currently in this folder, organized around a Wazuh-focused project rather than around publisher/source.

## Likely project focus

A strong project framing is:

> Improve Wazuh alert usefulness by adding context-aware enrichment, prioritization, and/or response support so analysts can focus on the alerts most likely to represent meaningful incidents.

For literature review purposes, "context-aware SIEM" should be treated as a family of related terms: alert triage, alert prioritization, SOC alert fatigue, security event correlation, cyber situational awareness, threat intelligence enrichment, attack path prediction, and adaptive detection.

## Group 1 - Core context-aware alert prioritization

These are the strongest conceptual references for the main problem.

| Paper | Use in review | Why it matters |
| --- | --- | --- |
| `Combating_alert_fatigue_with_AlertPro_Context-aware_alert_prioritization_using_reinforcement_learning_for_multi-step_attack_detection.pdf` | Core paper | Directly addresses alert fatigue, context-aware prioritization, analyst feedback, and multi-step attacks. |
| `Contextual_filtering_and_prioritization_of_computer_application_logs_for_security_situational_awareness.pdf` | Foundation paper | Useful for explaining contextual filtering and security situational awareness from logs. |
| `Providing_SIEM_systems_with_self_adaptation.pdf` | Foundation paper | Older but valuable because it frames SIEM correlation as context-aware and adaptive, especially for multi-step attacks. |
| `Toward_Context-Aware_Alert_Classification_in_Security_Operations_Centers_Using_LLMs.pdf` | Modern extension | Relevant if the project uses LLMs or separates organizational context from fixed SIEM rules. |

## Group 2 - Wazuh-specific detection and response

These should become the backbone if the implementation is built around Wazuh.

| Paper | Use in review | Why it matters |
| --- | --- | --- |
| `Automating_Malware_Detection_and_Response_via_Real-Time_Threat_Feed_Integration_with_Wazuh_SIEM.pdf` | Core Wazuh paper | Directly uses Wazuh, threat intelligence enrichment, VirusTotal/AbuseIPDB, custom correlation, and active response. |
| `Adaptive_Detection_of_Advanced_Persistent_Threats_APT_With_Graph_Neural_Networks_and_Rehearsal-Based_Continual_Learning_on_Wazuh_EDR_Telemetry.pdf` | Core Wazuh paper | Directly uses Wazuh telemetry and focuses on adaptive APT detection. |
| `Graph_Neural_Threat_Intelligence_Real-Time_Attack_Path_Prediction_Using_Event_Correlation_from_Wazuh_SIEM.pdf` | Core Wazuh paper, but verify quality | Very close to Wazuh + event correlation + graph-based attack path prediction. Check venue and peer-review status carefully. |

## Group 3 - Explainability and analyst usability

Use these to justify why prioritization should be understandable, not only accurate.

| Paper | Use in review | Why it matters |
| --- | --- | --- |
| `CyberShapley_explanation_prioritization_and_triage_of_cybersecurity_alerts_using_informative_graph_representation.pdf` | Strong supporting paper | Connects alert triage with explainable AI and graph representations. Useful for explaining why analysts need reasons behind rankings. |
| `A_Human_Centric_Risk-Based_Security_Alert_Prioritization_Using_Splunk.pdf` | Supporting analogy | Uses Splunk rather than Wazuh, but the risk-score/stress-score idea can transfer to Wazuh. |

## Group 4 - General SIEM alert management and ML

These help describe broader methods, but should not dominate the review unless your project is ML-heavy.

| Paper | Use in review | Why it matters |
| --- | --- | --- |
| `Advanced_Techniques_for_Alert_Management_in_Security_Information_and_Event_Management_Systems_With_Ensembled_Deep_Learning_Hybrid_Optimization_and_Multi-Feature_Extraction.pdf` | Broad technical background | Covers deep learning, fuzzy prioritization, and false positive/false negative reduction in SIEM alert management. |
| `ZenGuard_a_machine_learning_based_zero_trust_frame.pdf` | Optional related work | Useful only if the project includes Zero Trust, SOAR, UEBA, or automated mitigation. Otherwise keep it as adjacent work. |

## What is missing

The current folder is strong on alert prioritization and new AI/graph approaches. To make the literature review stronger for a Wazuh-focused project, add references in these areas:

1. Wazuh architecture and official capability documentation
2. Wazuh rule/decoder customization and MITRE ATT&CK mapping
3. Wazuh active response and external API/threat intelligence integrations
4. Benchmarking or evaluating Wazuh using adversary emulation
5. SOC alert fatigue surveys or human-AI SOC triage surveys
6. Datasets and testbeds for evaluating Wazuh alerts

## Suggested search phrases

Use these instead of only "context-aware SIEM":

```text
Wazuh alert prioritization
Wazuh alert triage
Wazuh SIEM threat intelligence integration
Wazuh VirusTotal AbuseIPDB active response
Wazuh MISP Suricata event correlation
Wazuh MITRE ATT&CK evaluation
Wazuh Atomic Red Team evaluation
Wazuh Caldera APT dataset
Wazuh machine learning threat detection
Wazuh graph neural network attack path prediction
SIEM alert fatigue SOC
security event correlation SIEM context
cyber situational awareness event correlation
contextual alert ranking SOC
risk-based alert prioritization SIEM
asset criticality alert prioritization
```

