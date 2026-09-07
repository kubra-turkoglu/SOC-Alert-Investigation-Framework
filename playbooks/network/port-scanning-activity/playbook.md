# Port Scanning Activity — Alert Investigation Playbook

## 1. Purpose

This playbook provides a structured, vendor-agnostic methodology for investigating **Port Scanning Activity** alerts across SIEM, EDR/XDR, firewall, and network telemetry sources.

The objective is to determine:

* Whether the activity is expected or suspicious
* Which host initiated the scanning activity
* Which systems and services were targeted
* Whether the activity was successful
* Whether the activity is part of a larger attack chain
* Whether additional investigation or escalation is required

The investigation is structured across three analyst levels:

**Tier 1 → Tier 2 → Tier 3**

---

# 2. Alert Overview

### Alert Name

**Port Scanning Activity**

### Primary MITRE ATT&CK Technique

**T1046 — Network Service Discovery**

Port scanning may be used to identify reachable systems, open ports, exposed services, and potential targets for subsequent exploitation or lateral movement.

### Typical Data Sources

| Source              | Investigation Value                                           |
| ------------------- | ------------------------------------------------------------- |
| SIEM                | Correlation, historical activity, cross-source investigation  |
| Firewall            | Connection attempts, allowed/blocked traffic, ports, policies |
| EDR                 | Process responsible for network activity                      |
| XDR                 | Endpoint + network correlation                                |
| Network telemetry   | Connection patterns and scanning behavior                     |
| Threat Intelligence | IP/domain reputation and known infrastructure                 |

---

# 3. Investigation Objectives

The investigation should answer the following questions:

1. **Who initiated the scan?**
2. **What systems were targeted?**
3. **Which ports/services were targeted?**
4. **Was the traffic allowed or blocked?**
5. **How extensive was the scan?**
6. **Is the source host authorized to perform scanning?**
7. **Which process generated the traffic?**
8. **What user was associated with the activity?**
9. **Did the source host perform other suspicious activity?**
10. **Did any successful connections occur after the scan?**
11. **Does the activity indicate reconnaissance only, or progression toward compromise/lateral movement?**

---

# 4. Investigation Flow

```text
                    PORT SCANNING ALERT
                            |
                            v
                    Validate Alert
                            |
             +--------------+--------------+
             |                             |
             v                             v
       Expected Source?              Unknown Source
             |                             |
        +----+----+                        v
        |         |                  Identify Source
       YES        NO                       |
        |         |                       v
        v         +----------------> Investigate Host
 Authorized?                            |
        |                               v
   +----+----+                     EDR / XDR
   |         |                         |
  YES        NO                        v
   |         |                   Identify Process
   v         v                         |
 Close     Investigate                 v
                                   Scope Activity
                                        |
                                        v
                              Correlate Other Events
                                        |
                                        v
                              Malicious / Suspicious?
                                  /             \
                                NO               YES
                                |                 |
                                v                 v
                         False Positive       Incident
                              /                 |
                       Expected Activity       v
                                           Containment
                                               |
                                               v
                                           Escalation
```

---

# 5. Tier 1 — Initial Triage

## 5.1 Validate the Alert

First verify that the alert represents actual network scanning activity.

Collect:

* Source IP
* Source hostname
* Source user
* Destination IP
* Destination hostname
* Destination port
* Protocol
* Timestamp
* Number of connections
* Number of unique destinations
* Number of unique ports
* Connection status
* Firewall action
* Detection rule that generated the alert

### Initial Questions

* Is the source internal or external?
* Is the destination internal or external?
* Is the source a server, workstation, security appliance, or scanner?
* Is the source part of an approved vulnerability-management infrastructure?
* Is the activity occurring during an expected maintenance or scanning window?

---

# 6. Identify the Scanning Pattern

Port scanning can appear in several forms.

### Vertical Scan

One source scans many ports on a single host.

```text
Attacker
   |
   +----> Server A : 22
   +----> Server A : 80
   +----> Server A : 443
   +----> Server A : 445
   +----> Server A : 3389
```

### Horizontal Scan

One source scans the same port across many hosts.

```text
Attacker
   |
   +----> Host A : 445
   +----> Host B : 445
   +----> Host C : 445
   +----> Host D : 445
```

### Network / Subnet Scan

One source probes multiple hosts and multiple ports.

```text
                +--> Host A --> 22 / 80 / 443
                |
Scanner --------+--> Host B --> 22 / 445 / 3389
                |
                +--> Host C --> 53 / 80 / 443
                |
                +--> Host D --> 135 / 139 / 445
```

The scanning pattern should be documented because it can provide context about the attacker's objective.

---

# 7. Tier 1 — Source Validation

Determine whether the source is legitimate.

### Potentially Legitimate Sources

* Vulnerability scanners
* Network discovery systems
* Security assessment tools
* IT troubleshooting systems
* Monitoring infrastructure
* Penetration-testing infrastructure
* Authorized administrative systems

### Potentially Suspicious Sources

* User workstation
* Recently created endpoint
* Unknown internal host
* Unmanaged device
* External IP address
* Endpoint with suspicious process execution

### Important Question

> Is this source expected to perform network discovery?

If **yes**, document the justification and validate that the observed activity matches the expected scope.

If **no**, continue with endpoint and network investigation.

---

# 8. Tier 1 — Initial Decision

### Close as Expected / Benign

Consider closure when:

* Source is an authorized scanner
* Activity matches an approved scanning window
* Target range is expected
* No suspicious endpoint activity is observed
* No unauthorized access is identified

Document:

* Why the activity was legitimate
* Which system performed the scan
* Expected scanning scope
* Evidence supporting the decision

### Escalate to Tier 2

Escalation should be considered when:

* Source is not an approved scanner
* A workstation is scanning internal systems
* Multiple internal systems are targeted
* Sensitive services are targeted
* Connections were allowed
* Suspicious processes are identified
* Additional security alerts correlate with the activity
* The source has no legitimate business reason to perform scanning

---

# 9. Tier 2 — Network Investigation

Tier 2 should expand the investigation beyond the original alert.

## 9.1 Firewall Investigation

Search firewall telemetry using the source IP.

Review:

* Source IP
* Destination IP
* Destination port
* Protocol
* Action: allowed / denied
* Firewall policy
* Source zone
* Destination zone
* NAT information
* Session information
* Connection frequency
* First seen / last seen

### Key Questions

* Were connections blocked or allowed?
* Which destinations accepted connections?
* Were critical systems targeted?
* Was the scanning activity limited to one subnet?
* Did the source communicate with the same systems before the alert?
* Did successful connections occur after the scanning activity?

---

# 10. Scope the Activity

Do not investigate only the destination shown in the original alert.

Search for the source IP across a broader time range.

### Minimum Scope

* Original destination
* Additional destinations
* Additional ports
* Other protocols
* Other security alerts
* Historical activity

### Recommended Historical Review

Review approximately **30 days of historical activity** when available.

Determine:

* First observed scanning activity
* Frequency of similar activity
* Previously targeted systems
* Whether the source has repeatedly performed scanning
* Whether the activity is new behavior for the host

---

# 11. Tier 2 — Endpoint Investigation

If the source IP belongs to an endpoint, pivot into EDR/XDR.

Identify:

* Hostname
* Logged-in user
* Process name
* Process ID
* Parent process
* Command line
* Process creation time
* Executable path
* File reputation
* Digital signature
* Network connections
* Child processes

### Important Question

> Which process actually generated the scanning traffic?

The network alert alone does not establish how the scan was performed.

Possible sources include:

* Nmap
* PowerShell
* Python
* Custom scripts
* Administrative tools
* Security tools
* Malicious executables

The presence of a legitimate scanning utility does not automatically make the activity benign. Context and authorization must still be established.

---

# 12. Process Tree Investigation

Example:

```text
explorer.exe
     |
     +---- powershell.exe
              |
              +---- python.exe
                       |
                       +---- scanner.exe
                                |
                                +---- Network Connections
```

Investigate:

* Parent-child relationship
* Command-line arguments
* Execution location
* User context
* File creation time
* File reputation
* Process signer
* Other processes created around the same time

### Suspicious Indicators

* Scanner executed from `%TEMP%`
* Newly created executable
* Unsigned executable
* Obfuscated PowerShell
* Script launched from an Office document
* Unusual parent process
* Execution by a standard user
* Scanner executed shortly after phishing or malware activity

---

# 13. Correlation With Other Security Events

Port scanning should not automatically be treated as an isolated incident.

Search for activity before and after the scan.

### Correlate With

* Authentication failures
* Successful authentication
* RDP activity
* SMB connections
* Remote service activity
* PowerShell execution
* Suspicious process creation
* Malware detections
* Privilege escalation
* Credential-access alerts
* C2 communication
* Vulnerability exploitation attempts

### Example Attack Chain

```text
Initial Access
      |
      v
Compromised Endpoint
      |
      v
Network Service Discovery
      |
      v
Port Scanning
      |
      v
SMB / RDP Discovery
      |
      v
Credential Access
      |
      v
Lateral Movement
```

This distinction is important:

**Port scanning alone may indicate reconnaissance.**

**Port scanning followed by successful access attempts may indicate an active attack.**

---

# 14. Tier 3 — Advanced Investigation

Tier 3 should determine the broader attack context and improve detection capability.

## 14.1 Determine Attack Scope

Identify:

* All source systems
* All targeted systems
* All targeted ports
* Successful connections
* Failed connections
* Related users
* Related processes
* Related alerts
* Earliest known activity
* Latest known activity

For example, an investigation should not stop after identifying the initial destination.

A broader investigation may reveal:

```text
Source Host
     |
     +--> Host 1 : RDP
     +--> Host 2 : SMB
     +--> Host 3 : HTTPS
     +--> Host 4 : SMB
     +--> Host 5 : RDP
```

The additional hosts may significantly change the incident severity.

---

# 15. Historical Investigation

Perform historical searches for the source IP, hostname, user, and process.

### Questions

* Has this source performed similar activity previously?
* When was it first observed?
* Was it previously associated with other alerts?
* Did the scanning target the same systems?
* Was there a change in behavior?
* Did the host begin scanning shortly after another suspicious event?

Historical activity can help distinguish:

**Established security infrastructure**

from

**Newly compromised infrastructure.**

---

# 16. Detection Logic

A basic port-scanning correlation can be represented as:

```text
IF

unique_destination_ips > threshold

OR

unique_destination_ports > threshold

WITHIN

time_window

AND

connection_rate > expected_baseline

AND

source NOT IN approved_scanners

THEN

generate Port Scanning Activity alert
```

Thresholds should be tuned according to the organization's environment.

A single threshold should not be treated as universally applicable.

---

# 17. Correlation Strategy

A stronger detection should combine multiple signals instead of relying only on connection count.

```text
             Network Connections
                     |
                     v
          +----------+----------+
          |                     |
          v                     v
   Unique Destinations     Unique Ports
          |                     |
          +----------+----------+
                     |
                     v
              Connection Rate
                     |
                     v
             Approved Scanner?
                /        \
              YES         NO
              |            |
              v            v
          Lower Risk    Investigate
                           |
                           v
                    Endpoint Process
                           |
                           v
                    Related Alerts
```

---

# 18. False Positive Analysis

Common false-positive scenarios include:

* Authorized vulnerability scanning
* Security assessments
* Penetration testing
* Asset discovery
* Network monitoring
* IT troubleshooting
* Infrastructure health checks
* Approved security tools

Before closing an alert, verify the source against:

* Asset inventory
* Vulnerability-management records
* Change-management records
* Security-team activities
* Maintenance windows
* Known scanner IPs

---

# 19. Indicators of Malicious Activity

Increase suspicion when multiple indicators are present.

### Network Indicators

* Large number of destinations
* Large number of ports
* High connection rate
* Internal subnet scanning
* Scanning of critical infrastructure
* Repeated scanning
* Successful connections following reconnaissance

### Endpoint Indicators

* Unknown scanning executable
* Suspicious process tree
* PowerShell or script-based scanning
* Execution from temporary directories
* Newly created executable
* Unsigned binary
* Suspicious user context

### Behavioral Indicators

* Scan followed by SMB/RDP connections
* Authentication attempts after scanning
* Credential-access activity
* Privilege escalation
* Malware detection
* C2 communication

---

# 20. Severity Guidance

Severity should be adapted to the organization's environment.

| Scenario                                      | Suggested Severity |
| --------------------------------------------- | ------------------ |
| Authorized vulnerability scanner              | Informational      |
| External scan, traffic blocked                | Low                |
| Unknown external scanner                      | Low–Medium         |
| Unknown internal host scanning a few systems  | Medium             |
| Internal host scanning a subnet               | High               |
| Scanning + suspicious process                 | High               |
| Scanning + successful access/lateral movement | Critical           |

Severity should consider **asset criticality, scope, success of connections, and correlated activity**, not scanning volume alone.

---

# 21. Evidence Collection

Collect and preserve:

### Network Evidence

* Source IP
* Destination IPs
* Ports
* Protocols
* Firewall actions
* Connection timestamps
* Session information

### Endpoint Evidence

* Hostname
* User
* Process tree
* Command line
* Executable path
* File hash
* Process timestamps
* Network connections

### Investigation Evidence

* Related alerts
* Historical activity
* Threat-intelligence results
* Screenshots where appropriate
* SIEM query results
* Timeline

---

# 22. Escalation Criteria

Escalate when:

* Source cannot be validated
* Activity is unauthorized
* Multiple systems are targeted
* Critical systems are targeted
* Connections were successful
* Suspicious processes are identified
* Other attack techniques are observed
* Evidence suggests lateral movement
* Evidence suggests compromise

The escalation should clearly communicate:

```text
WHAT happened
WHO/WHAT initiated it
WHEN it happened
WHAT was targeted
HOW extensive it was
WHETHER connections succeeded
WHAT additional evidence was found
WHY escalation is required
```

---

# 23. Case Disposition

Possible outcomes:

### Benign / Expected

Authorized scanning activity with supporting evidence.

### False Positive

Detection triggered by legitimate activity that does not represent a security incident.

### Suspicious Activity

Activity cannot be fully validated and requires further investigation.

### True Positive / Security Incident

Evidence indicates unauthorized or malicious reconnaissance and/or progression toward compromise.

---

# 24. Example Investigation Scenario

### Initial Alert

```text
Source:      10.10.20.45
Destination: 10.10.30.15
Port:        445
Action:      Allowed
```

Initial investigation identifies the source as an internal workstation.

Further investigation reveals:

```text
10.10.20.45
     |
     +--> 10.10.30.15 : 445
     +--> 10.10.30.16 : 445
     +--> 10.10.30.20 : 3389
     +--> 10.10.30.25 : 443
     +--> 10.10.30.30 : 445
```

A 30-day historical search identifies similar activity against additional internal systems.

EDR investigation identifies a previously unseen scanning process.

Firewall logs show that some connections were allowed.

The activity is therefore no longer treated as an isolated port-scan alert.

### Investigation Conclusion

**Suspicious / True Positive**, depending on the available evidence and organizational context.

Recommended actions may include:

* Escalation to Tier 2/Incident Response
* Containment of the source host where justified
* Blocking the source IP where appropriate
* Investigation of targeted systems
* Review of exposed services
* Investigation of the scanning process
* Review of related authentication and lateral-movement activity

---

# 25. Analyst Checklist

## Tier 1

* [ ] Validate source and destination
* [ ] Confirm timestamp
* [ ] Identify source hostname
* [ ] Identify source user
* [ ] Identify targeted ports
* [ ] Identify number of targets
* [ ] Check allowed/blocked status
* [ ] Determine whether source is an authorized scanner
* [ ] Perform initial enrichment
* [ ] Document findings
* [ ] Escalate when required

## Tier 2

* [ ] Search firewall logs
* [ ] Expand destination scope
* [ ] Search historical activity
* [ ] Review approximately 30 days when appropriate
* [ ] Investigate EDR/XDR telemetry
* [ ] Identify generating process
* [ ] Review process tree
* [ ] Review command line
* [ ] Correlate related alerts
* [ ] Build an activity timeline
* [ ] Determine attack scope

## Tier 3

* [ ] Validate attack hypothesis
* [ ] Identify root cause
* [ ] Investigate related hosts
* [ ] Perform threat hunting
* [ ] Review detection logic
* [ ] Identify detection gaps
* [ ] Tune thresholds/exclusions
* [ ] Recommend additional detections
* [ ] Document lessons learned

---

# 26. MITRE ATT&CK Mapping

### Primary Technique

**T1046 — Network Service Discovery**

### Potentially Related Techniques

| Technique                                    | Relevance                                |
| -------------------------------------------- | ---------------------------------------- |
| T1018 — Remote System Discovery              | Identifying additional systems           |
| T1049 — System Network Connections Discovery | Discovering network connections          |
| T1021 — Remote Services                      | Potential follow-up through RDP/SMB/etc. |

Related techniques should only be mapped when supported by investigation evidence.

---

# 27. Detection Engineering Opportunities

The investigation can be used to improve detection capability.

Potential improvements:

* Baseline normal scanners
* Maintain approved scanner allowlists
* Detect unusual internal scanning
* Correlate port count + destination count
* Add connection-rate analysis
* Correlate network activity with endpoint processes
* Detect scanning followed by remote-service connections
* Detect scanning of high-value assets
* Reduce false positives through asset context

---

# 28. Investigation Principle

> **Do not investigate the alert in isolation. Investigate the behavior around the alert.**

A port-scanning alert answers:

**“Something is probing network services.”**

A complete SOC investigation should answer:

**“Who performed the probing, why, what did they discover, what happened afterward, and whether the activity represents part of an attack.”**

---

# 29. Expected Investigation Output

The final case should provide a concise evidence-based conclusion:

```text
Source:
Source Host:
User:
Time Range:
Targets:
Ports:
Protocols:
Allowed Connections:
Blocked Connections:
Process:
Related Alerts:
Historical Activity:
Threat Intelligence:
Assessment:
Severity:
Disposition:
Recommended Actions:
```

---

# 30. Next Stage

This playbook is the investigation methodology.

The following components will extend it:

1. `investigation/tier-1.md`
2. `investigation/tier-2.md`
3. `investigation/tier-3.md`
4. `correlation/correlation-logic.md`
5. `correlation/queries/`
6. `detections/sigma/`
7. `detections/splunk/`
8. `detections/defender/`
9. `hunting/hunting-queries.md`
10. `flowchart.png`
11. `case-studies/benign.md`
12. `case-studies/malicious.md`
13. `references.md`
