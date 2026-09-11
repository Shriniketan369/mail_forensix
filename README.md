Mail ForensiX

<p align="center">
  <img src="logo.png" alt="Mail ForensiX" width="120">
</p>

<h1 align="center">Mail ForensiX</h1>

<p align="center">
  <strong>Explainable Email Forensics & Phishing Detection</strong>
</p>

<p align="center">
  Analyze raw emails, inspect authentication signals, detect phishing indicators,
  enrich sender IP intelligence, and generate an explainable forensic verdict.
</p>

<p align="center">
  <a href="https://github.com/Shriniketan369/mail_forensix">
    <img src="https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github" alt="GitHub Repository">
  </a>
  <img src="https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white" alt="HTML5">
  <img src="https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white" alt="CSS3">
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/Explainable%20Detection-6C63FF?style=for-the-badge" alt="Explainable Detection">
</p>

Overview

Mail ForensiX is a browser-based email forensics and phishing-analysis tool.

It takes a raw email, extracts forensic evidence, evaluates multiple phishing indicators, performs content-level analysis, enriches public sender IP information, and produces a human-readable security verdict.

Unlike a black-box classifier, Mail ForensiX exposes which indicators were triggered and why they affected the result.

Every flag is auditable. No black box.

Core Workflow

The complete analysis pipeline is:

flowchart TD
    A["Raw Email"] --> B["Email Parser"]

    B --> C["Header Analysis"]
    B --> D["Body Analysis"]
    B --> E["Sender IP Extraction"]

    C --> F["Detection Rubric"]
    D --> F

    D --> G["ML Text Analysis"]

    E --> H["GeoIP Lookup"]

    F --> I["Rule Score"]
    G --> J["ML Score"]

    I --> K["Score Fusion"]
    J --> K

    K --> L["Final Risk Score"]
    L --> M{"Risk Level"}

    M -->|0-25| N["Safe"]
    M -->|26-55| O["Suspicious"]
    M -->|56-100| P["Malicious"]

    N --> Q["Explainable Forensic Report"]
    O --> Q
    P --> Q

    H --> Q

GitHub natively renders Mermaid diagrams in Markdown files, so these diagrams are stored as editable Mermaid source rather than fragile screenshots. citeturn0search4turn0search0

Forensic Analysis Architecture

flowchart LR
    subgraph INPUT["INPUT"]
        A["Raw Email"]
    end

    subgraph PARSING["PARSING"]
        B["parser.js"]
        B1["Headers"]
        B2["Body"]
        B3["Authentication"]
        B4["URLs"]
        B5["Sender IP"]
    end

    subgraph DETECTION["DETECTION"]
        C["classifier.js"]
        C1["SPF"]
        C2["DKIM"]
        C3["DMARC"]
        C4["Reply-To"]
        C5["URL Signals"]
        C6["Social Engineering"]
    end

    subgraph INTELLIGENCE["INTELLIGENCE"]
        D["ml.js"]
        E["geoip.js"]
    end

    subgraph OUTPUT["OUTPUT"]
        F["Score Fusion"]
        G["Verdict"]
        H["Forensic Report"]
    end

    A --> B
    B --> B1
    B --> B2
    B --> B3
    B --> B4
    B --> B5

    B1 --> C
    B2 --> C
    B3 --> C
    B4 --> C
    B5 --> E

    B2 --> D

    C1 --> C
    C2 --> C
    C3 --> C
    C4 --> C
    C5 --> C
    C6 --> C

    C --> F
    D --> F
    E --> H

    F --> G
    G --> H

Detection Model

Mail ForensiX uses a hybrid, explainable scoring model.

flowchart LR
    A["Rule-Based Evidence"] --> B["60% Weight"]
    C["ML Text Signal"] --> D["40% Weight"]

    B --> E["Weighted Score Fusion"]
    D --> E

    E --> F["Final Score: 0-100"]

    F --> G{"Classification"}

    G -->|0-25| H["SAFE"]
    G -->|26-55| I["SUSPICIOUS"]
    G -->|56-100| J["MALICIOUS"]

Score Fusion

When the ML signal is available:

Final Score =
    (Rule Score × 0.60)
  + (ML Score × 0.40)

The rule-based signal receives the higher weight because authentication and structural email indicators provide deterministic forensic evidence, while text analysis is probabilistic.

Detection Rubric

The rule engine evaluates multiple independent indicators.

Indicator

Weight

SPF failure

20

DKIM failure

15

DMARC failure

15

From / Reply-To mismatch

20

Urgency language

15

Threat / consequence language

10

Sensitive-information request

20

Suspicious / non-HTTPS link

15

Brand / domain mismatch

15

Generic greeting

5

The rule score is capped at 100.

Because each rule has a visible condition and weight, an analyst can trace the result back to the evidence that produced it.

Risk Classification

Score

Verdict

Interpretation

0–25

🟢 Safe

Few or no significant phishing indicators

26–55

🟡 Suspicious

Multiple indicators require investigation

56–100

🔴 Malicious

Strong evidence of phishing or malicious intent

The score is an investigation aid and should not be treated as absolute proof.

What Mail ForensiX Analyzes

Email Headers

From

To

Reply-To

Subject

Sender IP

Authentication results

Relevant routing/header information

Authentication Signals

SPF

DKIM

DMARC

Content Signals

Urgency

Threats

Account suspension language

Credential requests

OTP/password requests

Verification language

Generic greetings

Social-engineering indicators

URL Signals

HTTP vs HTTPS

Suspicious URLs

Potentially deceptive domains

URL-based phishing indicators

Sender Intelligence

Public sender IP

Country

Region

City

ISP / organization

Coordinates

Timezone

Explainability

A major design goal of Mail ForensiX is to avoid producing an unexplained label.

Instead of:

Verdict: MALICIOUS

the system can provide an evidence trail such as:

Verdict: MALICIOUS

Triggered indicators:
✓ SPF authentication failure
✓ DMARC authentication failure
✓ From / Reply-To mismatch
✓ Urgency language detected
✓ Sensitive-information request
✓ Suspicious URL detected

Rule Score: 85
ML Score: 78
Final Score: 82.2

Recommended Action:
Treat the message as high risk and investigate before interacting
with links, attachments, or requested credentials.

This makes the output useful for analysts, demonstrations, and cybersecurity education.

Sender IP Intelligence

When a public sender IP can be extracted, Mail ForensiX can enrich the investigation with GeoIP data.

flowchart LR
    A["Raw Email"] --> B["Extract Sender IP"]
    B --> C{"Public IP?"}

    C -->|No| D["Mark as Private / Unavailable"]
    C -->|Yes| E["GeoIP Lookup"]

    E --> F["Country"]
    E --> G["Region"]
    E --> H["City"]
    E --> I["ISP / Organization"]
    E --> J["Latitude / Longitude"]
    E --> K["Timezone"]

    D --> L["Forensic Report"]
    F --> L
    G --> L
    H --> L
    I --> L
    J --> L
    K --> L

Note: IP geolocation is approximate. VPNs, proxies, cloud services, NAT, mail relays, and corporate gateways can make the geolocated address different from the actual sender.

Project Structure

mail_forensix/
│
├── index.html
│   └── Main application interface
│
├── styles.css
│   └── Application styling and responsive layout
│
├── app.js
│   └── UI workflow, dashboard, history and report generation
│
├── parser.js
│   └── Raw email/header parsing
│
├── classifier.js
│   └── Detection rubric, scoring and verdict generation
│
├── ml.js
│   └── ML-assisted email text analysis
│
├── geoip.js
│   └── Sender IP extraction and GeoIP enrichment
│
├── logo.png
│   └── Application logo
│
└── README.md
    └── Project documentation

Component Responsibilities

flowchart TB
    A["app.js<br/>Application Controller"]

    A --> B["parser.js<br/>Email Parsing"]
    A --> C["classifier.js<br/>Detection + Scoring"]
    A --> D["ml.js<br/>Text Analysis"]
    A --> E["geoip.js<br/>IP Intelligence"]

    B --> F["Structured Email Data"]
    C --> G["Rule Score + Red Flags"]
    D --> H["ML Probability / Signals"]
    E --> I["GeoIP Intelligence"]

    F --> J["Combined Analysis"]
    G --> J
    H --> J
    I --> J

    J --> K["Verdict + Confidence"]
    K --> L["Forensic Report"]

Example Investigation

A message such as:

Subject: URGENT: Your Account Will Be Suspended

Your account requires immediate verification.

Failure to verify your password and OTP within 24 hours
will result in permanent suspension.

Verify now:
http://example-login-support.com/verify

may trigger several independent signals:

flowchart TD
    A["Suspicious Email"] --> B["Urgency"]
    A --> C["Threat / Suspension"]
    A --> D["Credential Request"]
    A --> E["OTP Request"]
    A --> F["Suspicious URL"]

    B --> G["Detection Rubric"]
    C --> G
    D --> G
    E --> G
    F --> G

    G --> H["Elevated Risk Score"]
    H --> I["Explainable Verdict"]

The important point is that the system does not rely on one keyword. It combines multiple independent indicators.

Getting Started

Requirements

Modern web browser

Internet connection for GeoIP enrichment

No backend or package manager required for the current version

Clone

git clone https://github.com/Shriniketan369/mail_forensix.git
cd mail_forensix

Run

Open index.html directly in a browser.

For local development, use a static server:

python -m http.server 8000

Then open:

http://localhost:8000

Usage

Launch Mail ForensiX.

Paste a raw email into the analysis interface.

Start the analysis.

Review the parsed headers and body.

Inspect SPF, DKIM and DMARC results.

Review triggered phishing indicators.

Inspect the ML text signal.

Review sender IP intelligence when available.

Inspect the final score and verdict.

Read the explanation and recommended action.

Copy the generated forensic report if required.

Built-in sample emails can also be used for demonstrations.

Technology Stack

Layer

Technology

Interface

HTML5

Styling

CSS3

Application

Vanilla JavaScript

Email Parsing

Custom JavaScript

Detection

Weighted rule engine

Text Analysis

Client-side ML/text analysis

IP Intelligence

GeoIP API

Visualization

GitHub Mermaid

Deployment

Static web hosting

Security & Privacy

Mail ForensiX is intended for defensive cybersecurity analysis.

Important considerations

Email analysis is primarily performed in the browser.

Sender IP information may be sent to the configured GeoIP provider.

Do not submit confidential emails to an untrusted public deployment.

GeoIP information is approximate.

Detection results should be treated as decision-support evidence.

High-impact investigations should be validated with additional forensic and threat-intelligence sources.

Limitations

Mail ForensiX is a forensic-analysis prototype and is not intended to replace a production Secure Email Gateway or enterprise SOC platform.

Potential limitations include:

Incomplete or manipulated email headers

Missing authentication information

Legitimate third-party mail infrastructure

False positives from suspicious wording

False negatives against novel phishing campaigns

Approximate IP geolocation

Finite brand/domain intelligence

Client-side processing limitations

Roadmap

.eml file upload

Attachment analysis

URL reputation checks

Domain reputation and age analysis

DNS / MX analysis

Expanded brand impersonation detection

Threat-intelligence integrations

IOC extraction

PDF / JSON report export

Investigation case management

Persistent analysis history

Campaign clustering

Authentication-chain visualization

Advanced NLP / transformer-based classification

SIEM integration

Enterprise API

Responsible Use

Mail ForensiX is intended for:

Defensive cybersecurity

Phishing analysis

Email forensics

SOC training

Cybersecurity education

Security research

Authorized incident response

Cybersecurity competitions and demonstrations

Only analyze email and network information that you are authorized to investigate.

Contributing

Contributions are welcome.

git clone https://github.com/Shriniketan369/mail_forensix.git
cd mail_forensix
git checkout -b feature/your-feature

When submitting a pull request, please include:

What changed

Why it changed

How it was tested

Any security/privacy implications

License

No open-source license is currently specified in the repository.

If the project is intended for public distribution or external contributions, consider adding an appropriate license such as MIT, Apache-2.0, or GPL-3.0.

Repository

GitHub:
https://github.com/Shriniketan369/mail_forensix

Author:
Shriniketan369

The Principle

<p align="center">
  <strong>Every flag is auditable. No black box.</strong>
</p>

<p align="center">
  Mail ForensiX turns raw email evidence into an explainable security verdict.
</p>
