# Tier 1 Investigation — Port Scanning Activity

## 1. Purpose

This document defines the Tier 1 investigation procedure for a **Port Scanning Activity** alert.

The primary objective of Tier 1 is to:

1. Validate the alert
2. Identify the source and target
3. Determine whether the activity is expected
4. Perform initial enrichment
5. Identify obvious suspicious indicators
6. Determine the appropriate disposition
7. Escalate sufficiently suspicious activity to Tier 2

Tier 1 should focus on **fast, structured triage** rather than performing a complete incident investigation.

---

# 2. Investigation Philosophy

A port scanning alert should not be closed solely because the traffic volume is low or because the source is an internal IP.

The analyst should establish:

```text
WHO?
    ↓
WHAT?
    ↓
WHEN?
    ↓
WHERE?
    ↓
HOW?
    ↓
EXPECTED?
    ↓
SUSPICIOUS?
    ↓
CLOSE OR ESCALATE
```

The goal is to make an evidence-based decision.

---

# 3. Alert Intake

When the alert is received, record the information available directly from the detection.

### Required Fields

| Field            | Description                        |
| ---------------- | ---------------------------------- |
| Alert Name       | Detection that triggered the alert |
| Alert ID         | Unique case/alert identifier       |
| Timestamp        | Time of detected activity          |
| Source IP        | Originating IP address             |
| Destination IP   | Target IP address                  |
| Destination Port | Targeted service port              |
| Protocol         | TCP / UDP / ICMP / etc.            |
| Action           | Allowed / Blocked                  |
| Event Count      | Number of observed events          |
| Detection Source | SIEM / Firewall / EDR / XDR        |
| Severity         | Initial detection severity         |

Do not modify the original alert information.

---

# 4. Step 1 — Validate the Alert

Before investigating the source host, verify that the alert contains sufficient evidence of scanning behavior.

### Check

* Is the source IP valid?
* Is the destination IP valid?
* Is the timestamp correct?
* Is the destination port valid?
* Are multiple connection attempts present?
* Are multiple destinations involved?
* Are multiple ports involved?
* Is the traffic actually network traffic?
* Is the detection based on a single event or correlated events?

### Important

A single connection attempt to a single port does **not necessarily indicate port scanning**.

The detection should be evaluated in the context of:

* Number of targets
* Number of ports
* Connection frequency
* Time window
* Historical behavior

---

# 5. Step 2 — Identify the Source

Determine what the source IP belongs to.

### Identify

```text
Source IP
    ↓
Hostname
    ↓
Asset Type
    ↓
Asset Owner
    ↓
User
    ↓
Network Zone
```

### Questions

* Is the source internal or external?
* Is it a workstation?
* Is it a server?
* Is it a network appliance?
* Is it a security scanner?
* Is it a monitoring system?
* Is it a known administrative system?

---

# 6. Step 3 — Determine Whether the Source Is an Authorized Scanner

This is one of the most important Tier 1 checks.

Search the organization's known asset inventory, scanner list, or security tooling documentation.

### Common Authorized Scanner Types

Examples may include:

* Vulnerability scanners
* Network discovery tools
* Security assessment systems
* Penetration-testing infrastructure
* Monitoring systems
* Asset inventory systems

Examples of tools that may legitimately generate scanning traffic include:

* Nmap
* Nessus
* Qualys
* Rapid7

The presence of one of these tools does **not automatically mean the activity is benign**.

The analyst must determine whether the activity is authorized.

---

# 7. Step 4 — Check Expected Activity

Ask:

> **Does this source normally perform network scanning?**

Check available operational context.

### Possible Sources

* Asset inventory
* Vulnerability management platform
* Change-management records
* Maintenance schedules
* Security-team activities
* Penetration-test schedules
* Known scanner IP lists
* Internal documentation

### Expected Activity Indicators

```text
Known Scanner
     +
Authorized
     +
Expected Time
     +
Expected Target Range
     +
Expected Behavior
     =
Likely Benign
```

If the source is an approved scanner but the target range or timing is unusual, do not automatically close the alert.

---

# 8. Step 5 — Identify the Scan Scope

Determine how broad the activity is.

### Questions

* How many destination IPs were targeted?
* How many unique ports were targeted?
* How many connections occurred?
* What is the scan duration?
* Are targets located in the same subnet?
* Are critical systems included?

### Basic Classification

#### Single Host / Multiple Ports

```text
Source
  |
  +--> Server A : 22
  +--> Server A : 80
  +--> Server A : 443
  +--> Server A : 445
  +--> Server A : 3389
```

Potential **vertical scan**.

#### Multiple Hosts / Same Port

```text
Source
  |
  +--> Host A : 445
  +--> Host B : 445
  +--> Host C : 445
  +--> Host D : 445
```

Potential **horizontal scan**.

#### Multiple Hosts / Multiple Ports

```text
Source
  |
  +--> Host A : 22 / 80 / 443
  +--> Host B : 445 / 3389
  +--> Host C : 53 / 80
  +--> Host D : 135 / 139 / 445
```

Potential broader network reconnaissance.

---

# 9. Step 6 — Review Firewall Evidence

If firewall telemetry is available, search for the source IP.

### Review

* Source IP
* Destination IP
* Destination port
* Protocol
* Action
* Policy
* Source zone
* Destination zone
* Timestamp
* Number of sessions

### Determine

**Were the connections blocked or allowed?**

This distinction is important.

```text
Blocked Scan
    ↓
Reconnaissance Attempt
    ↓
Potentially Lower Risk

Allowed Scan
    ↓
Services May Be Reachable
    ↓
Potentially Higher Risk
```

This is not an automatic severity rule. Asset criticality and additional activity must also be considered.

---

# 10. Step 7 — Look for Additional Targets

Do not investigate only the destination shown in the original alert.

Pivot on the **source IP** and search for additional destinations within the relevant time window.

### Example

Initial alert:

```text
10.10.20.45 → 10.10.30.15:445
```

Additional search reveals:

```text
10.10.20.45 → 10.10.30.15:445
10.10.20.45 → 10.10.30.16:445
10.10.20.45 → 10.10.30.20:3389
10.10.20.45 → 10.10.30.25:443
10.10.20.45 → 10.10.30.30:445
```

The alert should now be treated as a broader scanning event rather than a single connection.

---

# 11. Step 8 — Identify High-Value Targets

Determine whether the source targeted sensitive infrastructure.

Examples:

* Domain Controllers
* Authentication servers
* File servers
* Database servers
* Management servers
* Security infrastructure
* Critical business applications
* Administrative interfaces

Scanning a critical asset may increase the investigation priority.

---

# 12. Step 9 — Initial Endpoint Check

If the source belongs to an endpoint and EDR/XDR telemetry is available, perform a basic endpoint pivot.

Tier 1 should initially determine:

* Hostname
* Logged-in user
* Recent suspicious alerts
* Active/recent suspicious processes
* Whether the host is already under investigation
* Whether malware has recently been detected

### Do Not Stop at the Network Alert

The important question is:

> **What was happening on the source host when the scanning activity occurred?**

---

# 13. Step 10 — Review Related Alerts

Search the source host and user for related security alerts.

### Look For

* Malware detection
* Suspicious PowerShell
* Suspicious process execution
* Credential-access alerts
* Authentication anomalies
* RDP activity
* SMB activity
* Lateral movement
* C2 communication
* Privilege escalation

### Time Relationship

Pay particular attention to:

```text
BEFORE SCAN
     ↓
Suspicious Activity
     ↓
PORT SCAN
     ↓
AFTER SCAN
     ↓
Remote Access / Authentication / Exploitation
```

A scan associated with other suspicious activity should generally receive more attention than an isolated scan.

---

# 14. Step 11 — Threat Intelligence Enrichment

If the source is external, perform appropriate enrichment.

Check:

* IP reputation
* Known malicious infrastructure
* ASN
* Geolocation
* Previous observations
* Abuse reports
* Threat-intelligence confidence

### Important

Threat intelligence should be treated as **supporting evidence**, not the sole basis for closing or escalating an alert.

For example:

```text
Unknown IP
    +
No malicious reputation
```

does **not** mean:

```text
Benign
```

Likewise:

```text
Known malicious IP
```

does not by itself explain the complete impact of the activity.

---

# 15. Step 12 — Identify Suspicious Indicators

The following should increase suspicion.

### Source

* Unknown internal workstation
* Unmanaged endpoint
* External source with suspicious reputation
* Recently provisioned host
* Host with no legitimate reason to scan

### Network

* Large number of targets
* Large number of ports
* High connection rate
* Scanning across multiple subnets
* Critical assets targeted
* Connections allowed
* Repeated scanning

### Endpoint

* Unknown executable
* Suspicious process
* Script-based scanner
* PowerShell activity
* Execution from temporary directories
* Newly created files
* Suspicious parent-child process relationship

### Correlation

* Scan followed by SMB/RDP
* Authentication attempts after scanning
* Malware alert
* Credential-access alert
* Privilege escalation
* C2 activity

---

# 16. Step 13 — False Positive Assessment

Before closing the alert, determine whether there is a reasonable benign explanation.

### Common Causes

| Cause                  | Validation                           |
| ---------------------- | ------------------------------------ |
| Vulnerability scanning | Check scanner ownership and schedule |
| Penetration test       | Check security/change records        |
| Asset discovery        | Check inventory tooling              |
| Monitoring             | Check monitoring infrastructure      |
| IT troubleshooting     | Validate with asset owner/team       |
| Security assessment    | Validate authorized activity         |

### Do Not Use

> "It looks like Nmap, so it is benign."

Instead use:

> "The source is an authorized vulnerability scanner and the observed targets and timestamp match the approved scanning activity."

The second conclusion is evidence-based.

---

# 17. Step 14 — Initial Risk Assessment

Tier 1 should consider at least four dimensions:

```text
                RISK
                  |
      +-----------+-----------+
      |           |           |
    SOURCE      SCOPE       TARGET
      |           |           |
 Internal?    Hosts?      Critical?
External?     Ports?      Sensitive?
Known?        Rate?
                  |
               RESULT
                  |
           Correlated Activity
```

### Example Guidance

| Situation                                     | Initial Assessment     |
| --------------------------------------------- | ---------------------- |
| Authorized scanner, expected activity         | Informational / Benign |
| External scan, blocked                        | Low                    |
| Unknown external source                       | Low–Medium             |
| Unknown internal workstation                  | Medium                 |
| Internal subnet scanning                      | Medium–High            |
| Critical infrastructure targeted              | High                   |
| Scanning + suspicious endpoint activity       | High                   |
| Scanning + successful access/lateral movement | Critical               |

These values are **guidance**, not universal severity rules.

---

# 18. Step 15 — Tier 1 Decision

At the end of triage, choose one of the following outcomes.

## A. Close — Expected Activity

Use when:

* Source is authorized
* Activity is expected
* Target range is expected
* Timing is expected
* No suspicious correlated activity exists

### Required Documentation

Record:

```text
Source:
Reason for authorization:
Expected activity:
Target scope:
Evidence:
Disposition:
```

---

## B. Close — False Positive

Use when:

* Detection logic triggered on legitimate activity
* Activity does not represent a security incident
* Evidence supports the benign explanation

Document why the detection fired and why the activity was determined to be non-malicious.

---

## C. Escalate — Suspicious Activity

Escalate to Tier 2 when:

* Source is unknown
* Source is not authorized to scan
* Internal workstation is scanning infrastructure
* Scan scope is unusual
* Critical systems are targeted
* Connections were allowed
* Suspicious endpoint activity is identified
* Related alerts are present
* The source's behavior is inconsistent with its baseline

---

## D. Escalate — Potential Incident

Escalate immediately when there are strong indicators of compromise or active attack progression.

Examples:

```text
Port Scan
    +
Suspicious Process
    +
Successful SMB/RDP Connection
```

or:

```text
Port Scan
    +
Credential Access
    +
Lateral Movement
```

At this point, the investigation should move beyond normal Tier 1 triage.

---

# 19. Tier 1 Escalation Package

Do not simply write:

> "Looks suspicious, escalating."

Provide the next analyst with enough information to continue without repeating the initial investigation.

### Escalation Template

```text
Alert:
Port Scanning Activity

Time:
YYYY-MM-DD HH:MM:SS UTC

Source:
10.10.20.45

Hostname:
WORKSTATION-XX

User:
user@example

Source Type:
Internal Workstation

Targets:
10.10.30.15
10.10.30.16
10.10.30.20
10.10.30.25

Ports:
445, 3389, 443

Connection Status:
Allowed / Blocked

Scan Scope:
Multiple internal hosts

Authorized Scanner:
No evidence of authorization identified

Endpoint Findings:
Suspicious process observed

Related Alerts:
Suspicious PowerShell execution

Initial Assessment:
Unauthorized internal network scanning with correlated
endpoint activity.

Severity:
High

Disposition:
Escalated to Tier 2

Recommended Next Step:
Investigate source endpoint process tree and correlate
network activity with authentication and remote-service events.
```

---

# 20. Tier 1 Investigation Flow

```text
              PORT SCANNING ALERT
                       |
                       v
                Validate Alert
                       |
                       v
               Identify Source
                       |
                       v
             Internal or External?
                /           \
             Internal      External
                |             |
                +------┬------+
                       |
                       v
              Authorized Scanner?
                 /          \
               YES           NO
                |             |
                v             v
        Validate Scope     Investigate
        and Timing          Further
                |             |
                +------┬------+
                       |
                       v
                 Identify Scope
                       |
                       v
              Check Firewall Logs
                       |
                       v
              Check Related Alerts
                       |
                       v
              Basic EDR/XDR Check
                       |
                       v
             Suspicious Indicators?
                  /           \
                NO             YES
                |               |
                v               v
          Benign / FP       Escalate T2
                |
                v
          Document & Close
```

---

# 21. Tier 1 Quick Checklist

### Alert Validation

* [ ] Alert timestamp verified
* [ ] Source IP identified
* [ ] Destination IP identified
* [ ] Destination ports identified
* [ ] Protocol identified
* [ ] Connection count reviewed
* [ ] Scan scope determined

### Source Validation

* [ ] Hostname identified
* [ ] Asset type identified
* [ ] User identified
* [ ] Internal/external status determined
* [ ] Authorized scanner status checked

### Network Investigation

* [ ] Firewall logs reviewed
* [ ] Allowed/blocked status checked
* [ ] Additional targets searched
* [ ] Additional ports searched
* [ ] Critical assets checked

### Correlation

* [ ] Related alerts reviewed
* [ ] Source host checked in EDR/XDR
* [ ] Suspicious process activity checked
* [ ] Authentication activity checked
* [ ] Remote-service activity checked

### Enrichment

* [ ] Asset context checked
* [ ] Threat intelligence checked where applicable
* [ ] Historical activity considered

### Decision

* [ ] Benign / Expected
* [ ] False Positive
* [ ] Suspicious
* [ ] Potential Incident
* [ ] Severity assigned
* [ ] Evidence documented
* [ ] Escalation package prepared if required

---

# 22. Tier 1 Definition of Done

A Tier 1 investigation is complete when the analyst can answer:

```text
WHO initiated the activity?
WHAT was scanned?
WHEN did it occur?
HOW extensive was the scan?
WAS the traffic allowed?
IS the source authorized to scan?
ARE there suspicious related events?
IS there evidence of compromise?
WHAT is the appropriate disposition?
```

If these questions cannot be answered with the available telemetry, the alert should generally be **escalated rather than closed without sufficient evidence**.

---

# 23. Tier 1 Output

The final Tier 1 case should contain:

```text
+---------------------------+
| Alert Summary             |
+---------------------------+
| Source                    |
| Destination(s)            |
| Ports                     |
| Time                      |
| Scope                     |
| Firewall Result           |
| Asset Context             |
| Authorization Status      |
| Related Activity          |
| Threat Intelligence       |
| Initial Risk Assessment   |
| Disposition               |
| Escalation Reason         |
+---------------------------+
```

The purpose of Tier 1 is not to prove the entire attack.

The purpose is to **rapidly establish whether the alert is expected, suspicious, or sufficiently concerning to require deeper investigation.**

