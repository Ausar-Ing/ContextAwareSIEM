# Feature Extraction Pipeline for Context Creation in a Context-Aware SIEM

## 1. Introduction

A traditional Security Information and Event Management (SIEM) system collects and correlates security logs from different sources, but many alerts are difficult to prioritize because they lack operational context. For example, a failed login attempt may be low priority for a normal user account, but high priority if it targets an administrator account on a critical production server.

The purpose of the feature extraction pipeline is to convert raw security events into rich context records. These context records describe the entities involved in an event, their historical behavior, environmental conditions, and associated risk factors. The generated context can then support alert prioritization, rule-based correlation, analyst investigation, and future machine learning extensions.

This report focuses on the feature extraction pipeline for context creation. The Graph Neural Network (GNN) component is considered a future enhancement and is not part of the core design described here.

## 2. Pipeline Objective

The main objective of the pipeline is to transform raw logs and external security data into structured, explainable, and reusable context records.

The pipeline should answer the following questions for each event:

- Who is involved?
- What happened?
- Where did it happen?
- When did it happen?
- Is this behavior normal or unusual?
- Are the involved users, hosts, or destinations high risk?
- What evidence explains the final risk level?

The output should not only contain numeric features, but also human-readable explanations that help security analysts understand why an event may be important.

## 3. High-Level Pipeline Architecture

The proposed pipeline consists of the following stages:

1. Data collection
2. Log normalization
3. Entity extraction
4. Entity resolution
5. Feature extraction
6. Time-window aggregation
7. Risk scoring
8. Context record creation
9. Context storage and delivery

The pipeline can be represented as:

```text
Raw Logs and External Data
        |
        v
Data Collection
        |
        v
Normalization
        |
        v
Entity Extraction and Resolution
        |
        v
Feature Extraction
        |
        v
Time-Window Aggregation
        |
        v
Risk Scoring and Explanation
        |
        v
Context Record Store
        |
        v
SIEM Dashboard, Alert Engine, Investigation Tools
```

## 4. Input Data Sources

The pipeline should collect data from both security logs and contextual data sources. Security logs describe what happened, while contextual sources explain why the event may or may not be important.

| Data Source | Purpose | Example Fields |
|---|---|---|
| Authentication logs | Detect login activity and account misuse | user, source IP, login status, MFA status |
| Firewall logs | Track allowed and blocked network connections | source IP, destination IP, port, protocol, action |
| DNS logs | Identify queried domains and suspicious destinations | domain, query type, response IP |
| Proxy logs | Monitor web traffic and URL access | URL, user, category, bytes transferred |
| Endpoint logs | Detect suspicious processes and file activity | host, process name, parent process, file hash |
| Cloud audit logs | Monitor activity in cloud environments | account, action, region, resource ID |
| Asset inventory | Add business and technical context | host type, owner, criticality, exposure |
| Identity directory | Add user and privilege context | role, department, admin status, account type |
| Vulnerability scanner | Identify weaknesses in involved assets | CVE, CVSS score, patch status |
| Threat intelligence | Identify known malicious indicators | IP reputation, domain reputation, malware hash |
| Historical activity store | Compare current activity with normal behavior | usual login time, common devices, normal destinations |

### Example Input Scenario

An authentication log reports that user `jsmith` successfully logged in from an unfamiliar external IP address at 02:14 AM. On its own, this may be treated as a normal login event. However, after adding context, the system may discover that:

- `jsmith` normally logs in between 08:00 and 18:00.
- The login came from a country not previously associated with the user.
- The account has access to sensitive financial systems.
- There were multiple failed login attempts before the successful login.

This additional context makes the event more suspicious and worthy of analyst attention.

## 5. Canonical Event Schema

Different systems produce logs in different formats. Before feature extraction, all logs should be converted into a common schema. This makes later processing consistent and reduces dependency on vendor-specific log formats.

### Proposed Canonical Event Fields

| Field | Description | Example |
|---|---|---|
| event_id | Unique event identifier | evt-789 |
| timestamp | Event time in UTC | 2026-08-29T02:14:00Z |
| event_type | Normalized event category | authentication.login |
| source_system | Original log source | Windows Event Log |
| source_ip | Source IP address | 203.0.113.55 |
| destination_ip | Destination IP address | 10.0.4.21 |
| user_id | User account involved | jsmith |
| host_id | Device or server involved | WORKSTATION-22 |
| action | Event action | login |
| status | Result of the action | success |
| protocol | Network protocol, if relevant | HTTPS |
| port | Destination port, if relevant | 443 |
| process_name | Process involved, if relevant | powershell.exe |
| raw_message | Original raw log message | Preserved for audit |

### Example: Raw Log to Normalized Event

Raw authentication log:

```text
Aug 29 02:14:08 vpn-gateway auth: user=jsmith src=203.0.113.55 result=success method=mfa
```

Normalized event:

```json
{
  "event_id": "evt-789",
  "timestamp": "2026-08-29T02:14:08Z",
  "event_type": "authentication.login",
  "source_system": "vpn-gateway",
  "source_ip": "203.0.113.55",
  "destination_ip": null,
  "user_id": "jsmith",
  "host_id": null,
  "action": "login",
  "status": "success",
  "authentication_method": "mfa",
  "raw_message": "Aug 29 02:14:08 vpn-gateway auth: user=jsmith src=203.0.113.55 result=success method=mfa"
}
```

## 6. Entity Extraction

Entity extraction identifies the important objects involved in each event. These entities become the basis for context creation.

### Main Entity Types

| Entity Type | Description | Examples |
|---|---|---|
| User | Human or service account | jsmith, svc-backup |
| Host | Endpoint, server, or cloud instance | WORKSTATION-22, prod-db-01 |
| IP address | Source or destination network address | 10.0.4.21, 203.0.113.55 |
| Domain | DNS name or web destination | example-login.com |
| URL | Full web resource | https://example-login.com/auth |
| Process | Executed process on a host | powershell.exe |
| File | File path or hash | invoice.exe, SHA256 hash |
| Application | Business or technical system | payroll-app, CRM |
| Cloud resource | Cloud asset or API target | s3-bucket-prod, iam-role-admin |

### Example Entity Extraction

Normalized event:

```json
{
  "event_type": "network.connection",
  "source_ip": "10.0.4.21",
  "destination_ip": "198.51.100.12",
  "host_id": "WORKSTATION-22",
  "user_id": "jsmith",
  "process_name": "powershell.exe",
  "port": 443
}
```

Extracted entities:

```json
{
  "user": "jsmith",
  "host": "WORKSTATION-22",
  "source_ip": "10.0.4.21",
  "destination_ip": "198.51.100.12",
  "process": "powershell.exe",
  "network_service": "HTTPS"
}
```

## 7. Entity Resolution

Entity resolution links different identifiers that refer to the same real-world entity. This is necessary because logs from different systems may use different names for the same user or device.

### Example: User Resolution

The following identifiers may all refer to the same user:

```text
jsmith
jsmith@company.com
COMPANY\jsmith
employee_id=1842
```

Resolved identity:

```json
{
  "entity_type": "user",
  "canonical_id": "user-1842",
  "display_name": "John Smith",
  "aliases": [
    "jsmith",
    "jsmith@company.com",
    "COMPANY\\jsmith",
    "employee_id=1842"
  ]
}
```

### Example: Host Resolution

The following identifiers may refer to the same endpoint:

```text
WORKSTATION-22
workstation-22.company.local
10.0.4.21
asset_id=A-5521
```

Resolved host:

```json
{
  "entity_type": "host",
  "canonical_id": "asset-A-5521",
  "hostname": "WORKSTATION-22",
  "ip_addresses": ["10.0.4.21"],
  "asset_owner": "Finance Department"
}
```

## 8. Feature Extraction Specification

Feature extraction converts normalized events and resolved entities into structured attributes that describe security relevance.

The feature set should be grouped into the following categories:

1. Event features
2. User context features
3. Host context features
4. Network context features
5. Temporal features
6. Behavioral baseline features
7. Risk features

## 9. Event Features

Event features describe the direct properties of the security event.

| Feature | Description | Example |
|---|---|---|
| event_type | Category of event | authentication.login |
| action | Action performed | login |
| status | Result of action | success |
| protocol | Network protocol | HTTPS |
| destination_port | Network port | 443 |
| bytes_out | Outbound data volume | 54000000 |
| process_name | Process involved | powershell.exe |
| parent_process | Parent process | winword.exe |
| command_length | Length of command line | 312 |
| action_allowed | Whether the action was allowed | true |

### Example Event Feature Output

```json
{
  "event_type": "endpoint.process_start",
  "process_name": "powershell.exe",
  "parent_process": "winword.exe",
  "command_length": 312,
  "uses_encoded_command": true,
  "action_allowed": true
}
```

## 10. User Context Features

User context features describe the account involved in the event.

| Feature | Description | Example |
|---|---|---|
| user_role | Business role of the user | Finance Analyst |
| department | Department or business unit | Finance |
| is_admin | Whether the user has admin privileges | false |
| is_service_account | Whether the account is non-human | false |
| mfa_enabled | Whether MFA is enabled | true |
| privilege_score | Numeric privilege level | 35 |
| recent_password_reset | Password changed recently | false |
| failed_logins_15m | Failed login count in last 15 minutes | 8 |
| normal_login_country | Common login country | Thailand |

### Example User Context Output

```json
{
  "user_id": "user-1842",
  "department": "Finance",
  "user_role": "Finance Analyst",
  "is_admin": false,
  "is_service_account": false,
  "mfa_enabled": true,
  "failed_logins_15m": 8,
  "privilege_score": 35
}
```

## 11. Host Context Features

Host context features describe the device, server, or cloud asset involved in the event.

| Feature | Description | Example |
|---|---|---|
| host_type | Type of asset | workstation |
| asset_criticality | Business importance | medium |
| internet_facing | Whether reachable from the internet | false |
| environment | Operational environment | production |
| owner_department | Asset owner | Finance |
| edr_installed | Endpoint protection installed | true |
| vulnerability_count | Number of open vulnerabilities | 4 |
| max_cvss_score | Highest vulnerability severity | 8.8 |
| patch_age_days | Days since last patch | 46 |
| previous_alerts_24h | Recent alerts on host | 3 |

### Example Host Context Output

```json
{
  "host_id": "asset-A-5521",
  "host_type": "workstation",
  "asset_criticality": "medium",
  "environment": "corporate",
  "internet_facing": false,
  "edr_installed": true,
  "vulnerability_count": 4,
  "max_cvss_score": 8.8,
  "patch_age_days": 46,
  "previous_alerts_24h": 3
}
```

## 12. Network Context Features

Network context features describe the reputation, location, and novelty of network activity.

| Feature | Description | Example |
|---|---|---|
| is_internal_destination | Destination is inside organization network | false |
| geo_country | Destination or source country | Netherlands |
| asn | Autonomous system number | AS14061 |
| is_tor_exit_node | IP is a Tor exit node | false |
| is_vpn_provider | IP belongs to VPN provider | true |
| ip_reputation_score | Threat intel risk score | 75 |
| domain_reputation_score | Domain risk score | 82 |
| domain_age_days | Age of domain | 12 |
| rare_destination_for_user | Destination is unusual for user | true |
| first_seen_destination | First time destination observed | true |

### Example Network Context Output

```json
{
  "destination_ip": "198.51.100.12",
  "is_internal_destination": false,
  "geo_country": "Netherlands",
  "asn": "AS14061",
  "is_vpn_provider": true,
  "ip_reputation_score": 75,
  "rare_destination_for_user": true,
  "first_seen_destination": true
}
```

## 13. Temporal Features

Temporal features describe when the event happened and whether the timing is unusual.

| Feature | Description | Example |
|---|---|---|
| hour_of_day | Event hour | 2 |
| day_of_week | Event day | Saturday |
| outside_working_hours | Event outside normal user hours | true |
| is_weekend | Whether event happened on weekend | true |
| time_since_last_login_minutes | Time since previous login | 740 |
| similar_events_5m | Similar events in last 5 minutes | 11 |
| similar_events_1h | Similar events in last hour | 26 |

### Example Temporal Feature Output

```json
{
  "hour_of_day": 2,
  "day_of_week": "Saturday",
  "outside_working_hours": true,
  "is_weekend": true,
  "similar_events_5m": 11,
  "similar_events_1h": 26
}
```

## 14. Behavioral Baseline Features

Behavioral baseline features compare current activity against historical behavior. These features are important because the same event can have different meanings depending on what is normal for the user or host.

| Feature | Description | Example |
|---|---|---|
| unusual_login_time | Login time differs from baseline | true |
| unusual_login_location | Login location differs from baseline | true |
| new_device_for_user | User has not used this device before | true |
| rare_process_for_host | Process rarely appears on this host | true |
| rare_destination_for_host | Host rarely contacts this destination | true |
| abnormal_data_volume | Data volume is higher than usual | true |
| peer_group_deviation | Behavior differs from similar users | high |

### Example Behavioral Baseline Output

```json
{
  "unusual_login_time": true,
  "unusual_login_location": true,
  "new_device_for_user": true,
  "rare_process_for_host": false,
  "rare_destination_for_host": true,
  "abnormal_data_volume": true,
  "peer_group_deviation": "high"
}
```

## 15. Risk Features

Risk features combine security context into values that can support prioritization.

| Feature | Description | Example |
|---|---|---|
| asset_risk_score | Risk based on asset value and exposure | 55 |
| user_risk_score | Risk based on privileges and account sensitivity | 35 |
| threat_intel_score | Risk from known bad indicators | 75 |
| vulnerability_risk_score | Risk from open vulnerabilities | 80 |
| behavior_anomaly_score | Risk from unusual behavior | 85 |
| alert_history_score | Risk from repeated related alerts | 60 |
| final_context_risk_score | Combined context score | 78 |

### Example Risk Feature Output

```json
{
  "asset_risk_score": 55,
  "user_risk_score": 35,
  "threat_intel_score": 75,
  "vulnerability_risk_score": 80,
  "behavior_anomaly_score": 85,
  "alert_history_score": 60,
  "final_context_risk_score": 78
}
```

## 16. Time-Window Aggregation

Some features require aggregation over time rather than extraction from a single event. The pipeline should support short-term, medium-term, and long-term windows.

| Window | Purpose | Example Features |
|---|---|---|
| 5 minutes | Detect bursts and rapid attacks | failed_logins_5m, dns_queries_5m |
| 15 minutes | Capture short attack patterns | failed_logins_15m, similar_events_15m |
| 1 hour | Identify ongoing suspicious behavior | unique_destinations_1h, alerts_1h |
| 24 hours | Daily operational context | previous_alerts_24h, data_volume_24h |
| 7 days | Short historical baseline | common_login_hours_7d |
| 30 days | Stable behavior baseline | normal_destinations_30d, peer_group_baseline |

### Example Aggregation

For a login event at `02:14 AM`, the pipeline checks the previous 15 minutes:

```json
{
  "event_id": "evt-789",
  "failed_logins_15m": 8,
  "unique_source_ips_15m": 3,
  "successful_logins_15m": 1,
  "brute_force_pattern": true
}
```

This tells the system that the successful login may be related to a brute force attempt.

## 17. Risk Scoring Approach

The first version of the system can use a weighted scoring model. This is easier to explain and validate than a complex machine learning model.

### Example Weighted Formula

```text
Final Risk Score =
  0.20 * User Risk Score +
  0.20 * Asset Risk Score +
  0.25 * Behavior Anomaly Score +
  0.20 * Threat Intelligence Score +
  0.10 * Vulnerability Risk Score +
  0.05 * Alert History Score
```

### Example Calculation

```text
User Risk Score:             35
Asset Risk Score:            55
Behavior Anomaly Score:      85
Threat Intelligence Score:   75
Vulnerability Risk Score:    80
Alert History Score:         60

Final Risk Score:
(0.20 * 35) + (0.20 * 55) + (0.25 * 85) + (0.20 * 75) + (0.10 * 80) + (0.05 * 60)
= 65.25
```

The score can then be mapped to severity levels:

| Score Range | Severity |
|---|---|
| 0-30 | Low |
| 31-60 | Medium |
| 61-80 | High |
| 81-100 | Critical |

In this example, the event would be classified as `High` because its final score is `65.25`.

## 18. Context Record Schema

The final output of the pipeline is a context record. This record contains the normalized event, extracted entities, contextual features, risk score, and explanation.

### Proposed Context Record

```json
{
  "context_id": "ctx-123",
  "event_id": "evt-789",
  "timestamp": "2026-08-29T02:14:08Z",
  "event_type": "authentication.login",
  "entities": {
    "user": {
      "id": "user-1842",
      "name": "jsmith",
      "department": "Finance"
    },
    "host": {
      "id": "asset-A-5521",
      "hostname": "WORKSTATION-22",
      "criticality": "medium"
    },
    "source_ip": {
      "address": "203.0.113.55",
      "country": "Netherlands",
      "reputation_score": 75
    }
  },
  "features": {
    "mfa_enabled": true,
    "failed_logins_15m": 8,
    "outside_working_hours": true,
    "unusual_login_location": true,
    "new_device_for_user": true,
    "is_vpn_provider": true,
    "previous_alerts_24h": 3
  },
  "risk": {
    "user_risk_score": 35,
    "asset_risk_score": 55,
    "behavior_anomaly_score": 85,
    "threat_intel_score": 75,
    "vulnerability_risk_score": 80,
    "alert_history_score": 60,
    "final_context_risk_score": 65.25,
    "severity": "High"
  },
  "explanations": [
    "The login occurred outside the user's normal working hours.",
    "The source IP is from an unusual country for this user.",
    "The user had 8 failed login attempts in the previous 15 minutes.",
    "The source IP is associated with a VPN provider.",
    "The involved host has recent related alerts."
  ],
  "metadata": {
    "feature_version": "v1.0",
    "pipeline_version": "v1.0",
    "created_at": "2026-08-29T02:14:12Z"
  }
}
```

## 19. End-to-End Example

### Scenario

A user successfully logs into the corporate VPN at 02:14 AM from a foreign IP address. The login was preceded by multiple failed attempts. The user belongs to the Finance department and the login source has suspicious reputation information.

### Step 1: Raw Event

```text
Aug 29 02:14:08 vpn-gateway auth: user=jsmith src=203.0.113.55 result=success method=mfa
```

### Step 2: Normalized Event

```json
{
  "event_id": "evt-789",
  "timestamp": "2026-08-29T02:14:08Z",
  "event_type": "authentication.login",
  "source_system": "vpn-gateway",
  "source_ip": "203.0.113.55",
  "user_id": "jsmith",
  "action": "login",
  "status": "success",
  "authentication_method": "mfa"
}
```

### Step 3: Resolved Entities

```json
{
  "user": {
    "canonical_id": "user-1842",
    "display_name": "John Smith",
    "department": "Finance",
    "role": "Finance Analyst"
  },
  "source_ip": {
    "address": "203.0.113.55",
    "country": "Netherlands",
    "is_vpn_provider": true,
    "reputation_score": 75
  }
}
```

### Step 4: Extracted Features

```json
{
  "outside_working_hours": true,
  "unusual_login_location": true,
  "failed_logins_15m": 8,
  "mfa_enabled": true,
  "is_admin": false,
  "department": "Finance",
  "is_vpn_provider": true,
  "ip_reputation_score": 75
}
```

### Step 5: Context and Risk Output

```json
{
  "context_id": "ctx-123",
  "event_id": "evt-789",
  "severity": "High",
  "final_context_risk_score": 65.25,
  "summary": "Successful VPN login from unusual foreign VPN provider after multiple failed attempts.",
  "explanations": [
    "Login occurred outside normal working hours.",
    "Source country is unusual for this user.",
    "There were 8 failed login attempts in the previous 15 minutes.",
    "Source IP is associated with a VPN provider.",
    "Source IP has elevated threat intelligence risk."
  ]
}
```

## 20. Storage Design

The system should separate raw logs, normalized events, extracted features, and final context records.

| Storage Component | Purpose |
|---|---|
| Raw Event Store | Keeps original logs for audit and reprocessing |
| Normalized Event Store | Stores cleaned events in canonical format |
| Entity Store | Stores resolved users, hosts, IPs, domains, and applications |
| Feature Store | Stores reusable feature values for entities and events |
| Context Store | Stores final context records used by the SIEM |

This separation makes the system easier to debug and allows the pipeline to reprocess old events when feature logic changes.

## 21. Explainability Requirements

Each generated context record should include explanations. This is important because security analysts need to trust and understand the system's output.

### Example Explanation Format

```json
{
  "risk_reason": "High-risk contextual login",
  "evidence": [
    {
      "feature": "outside_working_hours",
      "value": true,
      "explanation": "The login happened at 02:14 AM, outside the user's usual login window."
    },
    {
      "feature": "failed_logins_15m",
      "value": 8,
      "explanation": "Multiple failed attempts occurred before the successful login."
    },
    {
      "feature": "unusual_login_location",
      "value": true,
      "explanation": "The source country is not part of the user's historical login pattern."
    }
  ]
}
```

## 22. Data Quality and Validation

The pipeline should validate data before using it for context creation.

Important validation checks include:

- Required fields are present.
- Timestamps use a consistent timezone.
- IP addresses and domains are valid.
- User and host identifiers are resolved where possible.
- Duplicate events are detected.
- Missing values are handled consistently.
- External enrichment data is timestamped and not stale.

### Example Validation Rule

```text
If event_type = authentication.login:
  Required fields:
    - timestamp
    - user_id
    - source_ip
    - status
```

If required fields are missing, the event should still be stored, but the context record should include a data quality warning.

Example:

```json
{
  "data_quality_warnings": [
    "host_id is missing, so host context features could not be extracted."
  ]
}
```

## 23. Security and Privacy Considerations

The pipeline may process sensitive information such as usernames, IP addresses, device names, and business roles. Therefore, the system should apply security controls to both raw and processed data.

Recommended controls:

- Restrict access to raw logs and context records.
- Mask or hash sensitive identifiers where full values are not required.
- Keep audit logs for access to security data.
- Encrypt stored logs and feature records.
- Define retention periods for raw and enriched data.
- Avoid including unnecessary personal information in analyst-facing views.

## 24. Future Extension: GNN Integration

Although the GNN is outside the current scope, the proposed pipeline prepares the system for future graph-based analysis.

The resolved entities and extracted relationships can later be represented as a graph:

```text
User -> logged into -> Host
Host -> connected to -> IP
IP -> resolves from -> Domain
User -> belongs to -> Department
Host -> has -> Vulnerability
```

Future GNN models could use this graph to detect suspicious relationships, lateral movement, compromised accounts, or unusual communication patterns. However, the current pipeline remains useful without the GNN because it already produces structured and explainable context records.

## 25. Conclusion

The feature extraction pipeline is the core component responsible for turning raw security events into meaningful security context. By combining normalized logs, resolved entities, historical baselines, asset information, identity data, vulnerability data, and threat intelligence, the system can produce context records that help analysts prioritize alerts and investigate incidents more effectively.

The recommended design emphasizes:

- Consistent log normalization
- Accurate entity extraction and resolution
- Rich contextual feature categories
- Time-window aggregation
- Explainable risk scoring
- Versioned and reusable context records
- Storage separation for auditability and reprocessing

This design provides a practical foundation for a context-aware SIEM and can later be extended with graph-based or machine learning models when the core context creation pipeline is stable.
