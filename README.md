# SOC-Alert-Investigation-Framework

SOC-Alert-Investigation-Framework/
│
├── README.md
│
├── docs/
│   ├── SOC-Investigation-Methodology.md
│   ├── Alert-Triage-Framework.md
│   ├── Severity-and-Priority.md
│   ├── Escalation-Guidelines.md
│   ├── Evidence-Collection.md
│   └── Investigation-Checklist.md
│
├── playbooks/
│   │
│   ├── network/
│   │   ├── port-scanning/
│   │   ├── suspicious-dns/
│   │   ├── suspicious-network-connection/
│   │   ├── lateral-movement/
│   │   └── data-exfiltration/
│   │
│   ├── endpoint/
│   │   ├── suspicious-powershell/
│   │   ├── suspicious-process/
│   │   ├── encoded-command/
│   │   ├── persistence/
│   │   └── credential-access/
│   │
│   ├── identity/
│   │   ├── impossible-travel/
│   │   ├── brute-force/
│   │   ├── suspicious-login/
│   │   └── privilege-escalation/
│   │
│   ├── email/
│   │   ├── phishing/
│   │   ├── malicious-attachment/
│   │   └── malicious-url/
│   │
│   └── cloud/
│       ├── suspicious-login/
│       ├── privilege-escalation/
│       └── suspicious-api-activity/
│
├── detections/
│   ├── sigma/
│   ├── splunk/
│   ├── microsoft-defender/
│   └── correlation-searches/
│
├── hunting/
│   ├── network/
│   ├── endpoint/
│   ├── identity/
│   └── cloud/
│
├── evidence/
│   ├── sample-logs/
│   ├── screenshots/
│   └── investigation-artifacts/
│
├── diagrams/
│   ├── playbook-flowcharts/
│   └── investigation-workflows/
│
└── templates/
    ├── alert-investigation-template.md
    ├── incident-report-template.md
    ├── escalation-template.md
    └── closure-template.md
