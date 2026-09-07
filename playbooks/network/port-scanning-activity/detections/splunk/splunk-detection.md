# Splunk Detection — Port Scanning Activity

## 1. Purpose

This document defines Splunk detection logic for identifying potential port scanning activity across network traffic.

The detection is designed to identify hosts that establish connections to an unusually high number of:

* Destination IP addresses
* Destination ports
* IP/port combinations

within a defined time window.

The detection is intentionally vendor-neutral at the investigation level, while the implementation examples use Splunk Search Processing Language (SPL).

> **Important:** The thresholds used in this document are examples. Production thresholds should be based on the organization's normal network baseline, approved scanner inventory, network architecture, and false-positive rate.

---

# 2. Exact Splunk Implementation Assumptions

This section defines the assumptions used by the SPL examples in this document.

These assumptions are intentionally explicit so that a reader can understand **what must exist in Splunk before the detection can be deployed**.

## 2.1 Splunk Deployment

The examples assume:

* Splunk Enterprise or Splunk Cloud is available.
* The SOC has permission to search the relevant network and endpoint indexes.
* The detection is intended to run as a scheduled search or correlation search.
* The environment supports standard SPL commands such as:

  * `stats`
  * `eventstats`
  * `eval`
  * `where`
  * `lookup`
  * `sort`
  * `head`
  * `bin`
  * `tstats`

No assumption is made that Splunk Enterprise Security is installed unless explicitly stated.

If Splunk Enterprise Security is available, the resulting detection can additionally be implemented as a correlation search and mapped to a notable event / risk-based alert.

---

# 3. Data Source Assumptions

## 3.1 Network Data

The primary detection assumes that network connection telemetry is indexed in:

```text
index=network
```

This is an **example index name**, not a Splunk default.

The production environment may instead use:

```text
index=firewall
index=network_traffic
index=pan
index=fortigate
index=proxy
```

or another organization-specific index.

The SPL must therefore be adapted to the actual data source.

---

## 3.2 Required Network Fields

The baseline detection assumes the following fields exist:

| Field       | Expected Meaning              | Required    |
| ----------- | ----------------------------- | ----------- |
| `src_ip`    | Source IPv4/IPv6 address      | Yes         |
| `dest_ip`   | Destination IPv4/IPv6 address | Yes         |
| `dest_port` | Destination TCP/UDP port      | Yes         |
| `src_port`  | Source port                   | Recommended |
| `protocol`  | TCP / UDP / ICMP etc.         | Recommended |
| `action`    | Allowed / Blocked / Denied    | Recommended |
| `_time`     | Event timestamp               | Yes         |
| `bytes`     | Bytes transferred             | Optional    |
| `host`      | Splunk reporting host/device  | Recommended |
| `user`      | Associated identity           | Optional    |

The detection fundamentally depends on:

```text
src_ip
dest_ip
dest_port
_time
```

The remaining fields provide additional context.

---

# 4. Field Normalization Assumption

The detection assumes that equivalent fields have already been normalized.

For example:

```text
Firewall vendor field:
srcip

        ↓

Normalized field:
src_ip
```

and:

```text
Firewall vendor field:
dstport

        ↓

Normalized field:
dest_port
```

The repository uses generic field names deliberately so that the detection logic is not tied to a single firewall vendor.

---

# 5. Splunk CIM Assumption

Where Splunk Common Information Model (CIM) is deployed, the preferred implementation is to normalize network traffic into the appropriate CIM data model.

The detection assumes that:

```text
src_ip
dest_ip
dest_port
action
protocol
```

can either be searched directly or mapped from the organization's CIM implementation.

The repository does **not** assume that CIM is already configured.

Therefore:

```text
Raw Vendor Data
       ↓
Field Extraction
       ↓
CIM / Normalized Fields
       ↓
Detection
```

is the preferred architecture.

---

# 6. Index Assumption

The following index names are placeholders:

```text
index=network
index=endpoint
index=security
index=authentication
```

They are used consistently throughout the examples for readability.

### Production requirement

Replace these with the actual indexes or data models used by the organization.

For example:

```text
index=network_traffic
index=edr
index=security_alerts
index=windows_security
```

The repository should explicitly state that these are **implementation assumptions rather than Splunk defaults**.

---

# 7. Time Assumptions

The detection examples use relative time ranges such as:

```spl
earliest=-15m latest=now
```

This assumes:

* `_time` represents the event time.
* Splunk event timestamps are correctly parsed.
* Relevant data arrives within an acceptable ingestion delay.
* The scheduled search accounts for expected data latency.

For example, a production scheduled search may use:

```spl
earliest=-16m latest=-1m
```

instead of:

```spl
earliest=-15m latest=now
```

if approximately one minute of ingestion latency is expected.

The exact scheduling strategy should be determined from the environment's telemetry latency.

---

# 8. Time Zone Assumption

Splunk internally stores event time in epoch format.

The detection does not depend on a specific local timezone.

Analyst-facing timestamps should be rendered according to the SOC's agreed timezone, preferably:

```text
UTC
```

for cross-system investigation.

---

# 9. Source IP Assumptions

The detection assumes that `src_ip` represents the actual initiating system as accurately as the available telemetry permits.

This can be complicated by:

* NAT
* PAT
* Load balancers
* Proxies
* Network address translation gateways
* Shared infrastructure

For NAT environments, the detection should preferably correlate:

```text
src_ip
+
src_port
+
timestamp
+
firewall/session identifier
```

where available.

An IP address alone may not uniquely identify the originating endpoint.

---

# 10. Destination IP Assumptions

The `dest_ip` field is assumed to represent the actual target address observed by the network control.

The detection does not automatically determine whether an IP represents:

* Workstation
* Server
* Domain Controller
* Database
* Network device
* Internet host

Asset context must therefore be supplied through an asset inventory or lookup.

---

# 11. Port Assumptions

The detection assumes that:

```text
dest_port
```

contains a numeric TCP/UDP destination port where applicable.

Examples:

```text
22
53
80
135
139
443
445
3389
5985
5986
```

ICMP traffic does not have a destination port and should not be interpreted using the same cardinality logic.

---

# 12. Action Field Assumptions

Where firewall telemetry is used, the detection assumes that `action` can distinguish at least:

```text
allowed
blocked
denied
```

Actual vendor values may differ.

For example:

```text
accept
allow
permit
```

may need normalization to:

```text
allowed
```

Similarly:

```text
deny
drop
reject
```

may need normalization.

Detection logic should not assume vendor-specific values without validation.

---

# 13. Approved Scanner Lookup Assumption

The scanner exclusion logic assumes that an existing lookup is available:

```text
approved_scanners.csv
```

Expected fields:

```text
src_ip
scanner_name
owner
environment
approved
```

Example:

```text
src_ip,scanner_name,owner,environment,approved
10.10.50.10,Qualys,Security Team,Production,true
10.10.50.11,Nessus,Security Team,Production,true
```

The lookup should be maintained by the appropriate security or vulnerability-management team.

It should not be treated as a permanent static list.

---

# 14. Critical Asset Lookup Assumption

The critical-asset correlation assumes:

```text
critical_assets.csv
```

with fields such as:

```text
dest_ip
asset_name
asset_type
criticality
```

Example:

```text
dest_ip,asset_name,asset_type,criticality
10.10.30.10,DC01,Domain Controller,critical
10.10.30.20,FILE01,File Server,high
```

The lookup should be synchronized with the organization's asset inventory where possible.

---

# 15. Endpoint Data Assumptions

The process-correlation examples assume endpoint telemetry exists in:

```text
index=endpoint
```

and provides fields such as:

```text
host
user
process_name
parent_process_name
command_line
host_ip
```

These fields may originate from:

* EDR
* XDR
* Sysmon
* Windows Event Logs
* Endpoint security products

The detection does not assume a specific EDR vendor.

---

# 16. Host-to-IP Correlation Assumption

Network and endpoint telemetry may identify systems differently.

For example:

```text
Network:
src_ip=10.10.20.45
```

while endpoint telemetry may use:

```text
host=WORKSTATION-XX
```

A production implementation should maintain a reliable relationship between:

```text
IP address
↔ hostname
↔ asset
```

Possible sources include:

* Asset inventory
* DHCP logs
* DNS
* EDR inventory
* CMDB

The example `host_ip` field should therefore be considered an implementation-specific normalized field.

---

# 17. Data Quality Assumptions

The detection assumes:

* Network events are not systematically duplicated.
* `dest_ip` is extracted correctly.
* `dest_port` is extracted correctly.
* `_time` is accurate.
* Source and destination fields are not reversed.
* Firewall logs are not missing a significant percentage of sessions.
* Blocked and allowed events are distinguishable where required.
* Data ingestion latency is understood.

Before enabling the detection, the SOC should validate these assumptions against real telemetry.

---

# 18. Cardinality Assumptions

The baseline detection uses:

```spl
dc(dest_ip)
dc(dest_port)
```

to calculate unique targets and ports.

This assumes that distinct destination values represent meaningful scanning behavior.

The SOC should account for infrastructure where high cardinality is normal, such as:

* Proxy servers
* DNS resolvers
* Load balancers
* Monitoring systems
* Security scanners
* Network management systems

These systems may require separate baselines or exclusions.

---

# 19. Threshold Assumptions

The examples use:

```text
20 unique destinations
20 unique ports
100 connections
15-minute window
```

These are **demonstration values**, not universal security thresholds.

The production threshold should be determined using:

```text
Historical Baseline
+
Asset Role
+
Network Segment
+
Scanner Inventory
+
Observed False Positives
```

For example, a vulnerability scanner may normally contact thousands of systems.

A workstation may normally contact only a small number of internal systems.

The same threshold should not necessarily apply to both.

---

# 20. Scheduling Assumptions

The baseline detection is designed conceptually for a scheduled search.

Example:

```text
Search interval:
5 minutes

Search window:
15 minutes

Result:
One result per suspicious source/pattern
```

A production implementation should account for overlapping search windows.

For example:

```text
Search 1:
00:00–00:15

Search 2:
00:05–00:20

Search 3:
00:10–00:25
```

Without suppression or deduplication, the same scan may generate multiple alerts.

---

# 21. Deduplication Assumption

The recommended correlation key is approximately:

```text
src_ip
+
detection_type
+
time_window
```

Additional fields may be included where necessary:

```text
src_ip
+
dest_zone
+
detection_type
```

The implementation should avoid creating one alert for every individual connection.

The objective is:

```text
One scanning behavior
        ↓
One actionable alert
```

rather than:

```text
One scanning behavior
        ↓
Hundreds of alerts
```

---

# 22. Search Performance Assumptions

The detection assumes that the network index is appropriately indexed and searchable at the expected event volume.

For high-volume environments, production searches should prefer optimized approaches such as:

```spl
| tstats
```

against appropriate data models where practical.

A raw:

```spl
index=network
| stats ...
```

search across very large time ranges may be expensive.

Therefore:

```text
Development / Demonstration
        ↓
Raw SPL

Production / High Volume
        ↓
CIM + tstats / accelerated data model
```

is the preferred progression.

---

# 23. `join` Usage Assumption

The process-correlation example uses `join` for readability.

However, `join` can become expensive or introduce correlation limitations at scale.

For production implementations, consider alternatives such as:

* `stats`
* `eventstats`
* `append`
* `lookup`
* `tstats`
* Data Model acceleration
* Splunk Enterprise Security risk-based correlation

The repository's `join` example should therefore be treated as a conceptual implementation rather than the final performance-optimized production search.

---

# 24. Lookup Freshness Assumption

The following lookups must be maintained:

```text
approved_scanners.csv
critical_assets.csv
```

Recommended metadata:

```text
owner
last_reviewed
expiration
environment
```

A scanner exclusion without ownership or review information can become a permanent blind spot.

Where possible, exclusions should have an expiration/revalidation process.

---

# 25. IPv4 / IPv6 Assumption

The examples use IPv4 addresses:

```text
10.10.20.45
```

The detection logic itself should support IPv6 where the organization's network telemetry contains IPv6.

Do not hard-code private IPv4 ranges as the only valid source format.

---

# 26. Network Zone Assumption

Where available, the detection should enrich:

```text
src_zone
dest_zone
```

Examples:

```text
User
Server
DMZ
Management
Security
Internet
```

Zone information can significantly improve detection quality.

For example:

```text
Security Scanner → Server Zone
```

may be expected.

Whereas:

```text
User Workstation → Server Zone
```

may warrant additional investigation.

---

# 27. User Identity Assumption

The network event may not always contain a user.

Therefore:

```text
user
```

is considered optional at the network layer.

If identity is required, the source IP should be correlated with:

* EDR identity
* Authentication logs
* DHCP
* VPN
* NAC
* Active Directory
* Identity provider

The absence of a user field should not automatically prevent detection.

---

# 28. Severity Assumption

The detection itself should identify suspicious behavior.

It should not automatically declare:

```text
Port scan = malicious
```

Severity should incorporate context such as:

```text
Source Role
+
Scanner Authorization
+
Target Criticality
+
Allowed/Blocked
+
Endpoint Evidence
+
Authentication Evidence
+
Historical Behavior
```

---

# 29. Example Production Configuration

A realistic production implementation could use the following conceptual configuration:

```text
Detection Name:
Port Scanning Activity

Search Interval:
5 minutes

Search Window:
15 minutes

Minimum Unique Targets:
20

Minimum Unique Ports:
20

High Connection Rate:
100 connections / 5 minutes

Approved Scanner Exclusion:
Enabled

Critical Asset Enrichment:
Enabled

Endpoint Correlation:
Optional

Risk Scoring:
Enabled

Alert Suppression:
Enabled

Data Source:
Network Traffic / Firewall

Primary Technique:
MITRE ATT&CK T1046
```

These values represent the **initial implementation baseline for this repository**, not a universal production standard.

---

# 30. Baseline Detection

```spl
index=network
earliest=-15m latest=now
| stats
    count as connections
    dc(dest_ip) as unique_targets
    dc(dest_port) as unique_ports
    values(dest_port) as ports
    by src_ip
| where unique_targets >= 20 OR unique_ports >= 20
| sort - connections
```

This search assumes all of the data-source and field conditions documented above.

---

# 31. Horizontal Scan Detection

```spl
index=network
earliest=-15m latest=now
| stats
    count as connections
    dc(dest_ip) as unique_targets
    values(dest_ip) as targets
    by src_ip dest_port
| where unique_targets >= 20
| sort - unique_targets
```

---

# 32. Vertical Scan Detection

```spl
index=network
earliest=-15m latest=now
| stats
    count as connections
    dc(dest_port) as unique_ports
    values(dest_port) as ports
    by src_ip dest_ip
| where unique_ports >= 20
| sort - unique_ports
```

---

# 33. Connection Rate Detection

```spl
index=network
earliest=-5m latest=now
| stats
    count as connections
    dc(dest_ip) as unique_targets
    dc(dest_port) as unique_ports
    by src_ip
| where connections >= 100
| eval connections_per_minute = connections / 5
| sort - connections_per_minute
```

---

# 34. Allowed vs Blocked Scan Detection

```spl
index=network
earliest=-15m latest=now
| stats
    count as events
    dc(dest_ip) as unique_targets
    dc(dest_port) as unique_ports
    by src_ip action
| where unique_targets >= 20 OR unique_ports >= 20
| sort - events
```

---

# 35. Scanner Exclusion

```spl
index=network
earliest=-15m latest=now
| stats
    count as connections
    dc(dest_ip) as unique_targets
    dc(dest_port) as unique_ports
    by src_ip
| lookup approved_scanners.csv src_ip OUTPUT scanner_name approved
| where isnull(approved) OR approved!="true"
| where unique_targets >= 20 OR unique_ports >= 20
| sort - connections
```

---

# 36. Critical Asset Detection

```spl
index=network
earliest=-15m latest=now
| lookup critical_assets.csv dest_ip OUTPUT
    asset_name
    asset_type
    criticality
| where criticality IN ("high","critical")
| stats
    count as connections
    dc(dest_port) as unique_ports
    values(dest_port) as ports
    values(asset_name) as assets
    by src_ip dest_ip asset_name asset_type criticality
| where unique_ports >= 5
| sort - unique_ports
```

---

# 37. Scan + Remote Service Correlation

```spl
index=network
earliest=-30m latest=now
dest_port IN (22,139,445,3389,5985,5986)
| stats
    count as connections
    dc(dest_ip) as unique_targets
    values(action) as actions
    by src_ip dest_port
| where unique_targets >= 5
| sort - unique_targets
```

---

# 38. Process Correlation

Endpoint correlation assumes that the source IP can be reliably associated with an endpoint record.

```spl
index=endpoint
earliest=-15m latest=now
(
    process_name IN ("nmap.exe","nmap","powershell.exe","python.exe")
    OR command_line="*nmap*"
)
| stats
    values(host) as hosts
    values(user) as users
    values(parent_process_name) as parents
    values(command_line) as commands
    by process_name
```

This search is an enrichment mechanism and should not independently classify the activity as malicious.

---

# 39. Production Implementation Decision

The recommended implementation path is:

```text
Phase 1
Raw Network SPL
        ↓
Phase 2
Field Normalization
        ↓
Phase 3
Approved Scanner + Asset Lookups
        ↓
Phase 4
CIM / Data Model
        ↓
Phase 5
Risk-Based Correlation
        ↓
Phase 6
Endpoint / Identity Correlation
        ↓
Phase 7
Detection Tuning
```

This provides a realistic progression from a portfolio demonstration to an operational SOC detection.

---

# 40. Production Readiness Checklist

Before production deployment:

* [ ] Actual network index identified
* [ ] `src_ip` validated
* [ ] `dest_ip` validated
* [ ] `dest_port` validated
* [ ] `_time` validated
* [ ] `action` normalization validated
* [ ] Network event duplication checked
* [ ] Ingestion latency measured
* [ ] NAT behavior understood
* [ ] Scanner inventory created
* [ ] Critical asset inventory created
* [ ] Threshold baseline established
* [ ] Search performance tested
* [ ] CIM mapping validated where applicable
* [ ] Scheduled-search interval validated
* [ ] Alert suppression configured
* [ ] Endpoint correlation tested
* [ ] False-positive rate measured
* [ ] Detection owner assigned
* [ ] Detection review process established

---

# 41. Important Implementation Disclaimer

The SPL in this repository is intended to demonstrate **detection engineering methodology and investigation logic**.

It is not presented as copy-paste production code for every Splunk environment.

Before deployment, the following must be validated against the target environment:

```text
Index Names
Field Names
Data Sources
CIM Mapping
Time Parsing
Data Latency
Thresholds
Lookups
Asset Context
Scanner Exclusions
Search Performance
Alert Suppression
```

This distinction is important because a technically correct SPL query can still produce an ineffective detection if the underlying telemetry or environment assumptions are incorrect.

---

# 42. Summary

The detection assumes a Splunk environment in which network telemetry can reliably answer:

```text
WHO?
    src_ip

WHERE?
    dest_ip

WHAT?
    dest_port / protocol

WHEN?
    _time

RESULT?
    action

HOW MUCH?
    connection count / cardinality
```

Additional enrichment should answer:

```text
WHO OWNS THE SOURCE?
IS IT AN APPROVED SCANNER?
WHAT ASSETS WERE TARGETED?
WERE CONNECTIONS ALLOWED?
WHAT PROCESS GENERATED THE ACTIVITY?
WHAT HAPPENED BEFORE AND AFTER THE SCAN?
```

The resulting detection architecture is:

```text
              NETWORK TELEMETRY
                     │
                     ▼
             FIELD NORMALIZATION
                     │
                     ▼
              SCAN DETECTION
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Targets     Ports       Rate
          │          │          │
          └──────────┼──────────┘
                     ▼
             SCANNER EXCLUSION
                     │
                     ▼
              ASSET ENRICHMENT
                     │
                     ▼
          EDR / IDENTITY CORRELATION
                     │
                     ▼
               RISK SCORING
                     │
                     ▼
             SPLUNK ALERT / RISK
                     │
                     ▼
              TIER 1 INVESTIGATION
```

This makes the implementation assumptions explicit while preserving the repository's main principle:

> **The detection demonstrates a general SOC detection-engineering approach, not a vendor-specific copy-paste rule.**

