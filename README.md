Mail ForensiX

<p align="center">
  <img src="logo.png" alt="Mail ForensiX" width="110">
</p>

<h1 align="center">Mail ForensiX</h1>

<p align="center">
  <strong>Explainable Email Forensics & Phishing Detection</strong>
</p>

<p align="center">
  Analyze raw emails, identify phishing indicators, inspect authentication signals,
  trace sender IPs, and generate an explainable forensic verdict — all from a single web interface.
</p>

<p align="center">
  <a href="https://github.com/Shriniketan369/mail_forensix">
    <img src="https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github" alt="GitHub">
  </a>
  <img src="https://img.shields.io/badge/JavaScript-Vanilla-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/Frontend-HTML%20%7C%20CSS-E34F26?style=for-the-badge&logo=html5&logoColor=white" alt="Frontend">
  <img src="https://img.shields.io/badge/Analysis-Explainable%20AI-6C63FF?style=for-the-badge" alt="Explainable AI">
</p>

Overview

Mail ForensiX is a lightweight email-security and digital-forensics application designed to help analysts investigate suspicious messages.

Instead of returning an unexplained "Phishing" label, Mail ForensiX exposes the evidence behind its decision. It combines:

Email header and content parsing

Deterministic phishing-detection rules

ML-assisted suspicious-language analysis

SPF / DKIM / DMARC signal analysis

Sender IP extraction and GeoIP enrichment

Risk scoring and confidence

Human-readable forensic reasoning

Recommended analyst actions

Analysis history and dashboard statistics

The core design principle is simple:

Every flag should be explainable.

Why Mail ForensiX?

Traditional phishing classifiers can make a decision without making the reasoning obvious to the analyst.

Mail ForensiX takes a different approach.

It exposes the signals contributing to the verdict, allowing an investigator to answer:

What made this email suspicious?

Did authentication checks fail?

Does the From address conflict with Reply-To?

Is the sender claiming to represent a known brand from an unrelated domain?

Does the message contain credential-harvesting language?

Are there suspicious URLs?

What suspicious language was detected?

Where does the public sender IP geolocate?

What action should an analyst take next?

This makes the system suitable for security education, phishing triage, SOC demonstrations, hackathons, and forensic analysis prototypes.

Detection Pipeline

┌─────────────────┐
│    Raw Email    │
│  Headers + Body │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Email Parser   │
│ Headers / Body  │
│ Auth / IP / URL │
└────────┬────────┘
         │
         ├─────────────────────┐
         ▼                     ▼
┌─────────────────┐   ┌─────────────────┐
│ Detection       │   │ ML Text         │
│ Rubric          │   │ Analysis        │
│                 │   │                 │
│ SPF / DKIM      │   │ Suspicious      │
│ DMARC           │   │ wording /       │
│ URLs            │   │ tokens          │
│ Domain mismatch │   │                 │
│ Social          │   │                 │
│ engineering     │   │                 │
└────────┬────────┘   └────────┬────────┘
         │                     │
         └──────────┬──────────┘
                    ▼
           ┌──────────────────┐
           │ Score Fusion     │
           │                  │
           │ Rubric: 60%      │
           │ ML:     40%      │
           └────────┬─────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ Explainable Verdict     │
       │                         │
       │ Safe / Suspicious /     │
       │ Malicious               │
       └────────────┬────────────┘
                    │
                    ▼
           ┌──────────────────┐
           │ GeoIP Enrichment │
           │ Sender IP →      │
           │ Location / ISP   │
           └────────┬─────────┘
                    │
                    ▼
          ┌────────────────────┐
          │ Forensic Report    │
          │ Evidence + Reason  │
          │ + Recommendation   │
          └────────────────────┘

Key Features

1. Raw Email Forensics

Mail ForensiX parses raw email content and extracts useful forensic fields such as:

Sender

Recipient

Reply-To

Subject

Sender IP

Authentication results

Email body

Relevant header information

This converts an unstructured email into analyzable evidence.

2. Explainable Detection Rubric

The detection engine uses an explicit, weighted rule set rather than a hidden black-box model.

Current signals include:

Signal

Weight

SPF authentication failure

20

DKIM authentication failure

15

DMARC authentication failure

15

From / Reply-To mismatch

20

Urgency / pressure language

15

Threat / consequence language

10

Sensitive-information request

20

Suspicious / non-HTTPS link

15

Brand / sender-domain mismatch

15

Generic greeting

5

The rubric score is capped at 100.

Because each rule has an explicit test and weight, the decision process is inspectable and auditable.

3. ML-Assisted Text Analysis

The project includes a lightweight client-side text-analysis component that provides an additional phishing-probability signal based on message wording.

It can expose:

Phishing probability

Suspicious/high-impact tokens

Number of tokens evaluated

An independent content-level signal

The ML component is deliberately treated as an additional signal rather than the sole source of truth.

4. Hybrid Score Fusion

When the ML signal is available, the final score is calculated as:

Final Score = (Rubric Score × 0.60)
            + (ML Probability × 0.40)

The rule-based signal receives the larger weight because authentication and structural indicators are deterministic evidence, while language analysis is probabilistic.

If the ML component is unavailable, the application safely falls back to the rule-based score.

5. Risk Classification

Final Score

Verdict

0–25

🟢 Safe

26–55

🟡 Suspicious

56–100

🔴 Malicious

The application also produces:

Confidence

Reasoning

Triggered red flags

Recommended action

Underlying scores

6. Sender IP Intelligence

When a usable public sender IP is present, Mail ForensiX can enrich it with GeoIP information.

Potential enrichment includes:

IP address

City

Region

Country

Country code

ISP / organization

Latitude

Longitude

Timezone

Private/internal addresses are handled separately because they are not meaningful public geolocation targets.

7. Forensic Report Generation

The final analysis consolidates the available evidence into a readable report containing:

Verdict
Confidence
Reasoning
Red Flags
Authentication Results
Sender Information
Sender IP
GeoIP Information
Recommended Action

This makes the result suitable for a quick SOC-style triage workflow or a cybersecurity demonstration.

8. Analysis History & Dashboard

The frontend provides an analysis-oriented dashboard with support for:

Previous analysis results

Classification statistics

Quick access to sample emails

Report copying

Repeated investigation workflows

Architecture

Mail ForensiX is intentionally lightweight and currently runs as a client-side web application.

                 ┌───────────────────────────┐
                 │         index.html        │
                 │       Application UI      │
                 └─────────────┬─────────────┘
                               │
                 ┌─────────────▼─────────────┐
                 │          app.js           │
                 │ UI + Workflow + Reports   │
                 └───────┬─────────┬─────────┘
                         │         │
            ┌────────────▼───┐   ┌─▼──────────────┐
            │   parser.js    │   │ classifier.js  │
            │ Email parsing  │   │ Rule engine    │
            └────────────────┘   └───────┬────────┘
                                         │
                               ┌─────────▼─────────┐
                               │      ml.js        │
                               │ Text intelligence │
                               └───────────────────┘

                 ┌───────────────────────────┐
                 │         geoip.js         │
                 │ Sender IP enrichment     │
                 └─────────────┬─────────────┘
                               │
                               ▼
                         GeoIP service

Project Structure

mail_forensix/
│
├── index.html       # Main application interface
├── styles.css       # UI styling and responsive layout
├── app.js           # Application workflow, dashboard and reports
├── parser.js        # Raw email parsing and field extraction
├── classifier.js    # Explainable phishing rubric and score fusion
├── ml.js            # Client-side ML/text analysis
├── geoip.js         # Sender IP extraction and GeoIP enrichment
├── logo.png         # Application logo
└── README.md        # Project documentation

How the Detection Engine Works

Step 1 — Parse

The raw email is converted into structured information.

Step 2 — Evaluate Rules

Each forensic rule independently checks for a suspicious condition.

For example:

{
  id: "spf_fail",
  weight: 20,
  test: (p) => p.spf === "fail"
}

A triggered rule contributes its configured weight to the rubric score.

Step 3 — Analyze Content

The email body is passed through the ML/text-analysis layer to identify suspicious wording patterns.

Step 4 — Fuse Signals

The rule-based and ML signals are combined:

60% deterministic forensic evidence
40% content-level ML signal

Step 5 — Generate Verdict

The final score determines the risk category.

Step 6 — Explain

The application maps triggered rules to human-readable explanations and generates an analyst recommendation.

Example

Consider a message containing:

From: security@example-support.com
Reply-To: recovery@example-support.com

Subject: Urgent Account Verification Required

Your account will be suspended within 24 hours.
Verify your password and OTP immediately:

http://example-support-login.com/verify

Potential signals include:

✓ Urgency language
✓ Threat / account-suspension language
✓ Sensitive-information request
✓ Non-HTTPS URL
✓ Suspicious verification URL
✓ Possible sender-domain mismatch

Mail ForensiX combines these signals with available authentication results and ML content analysis to produce the final verdict.

Getting Started

Requirements

No package manager or backend is required for the current version.

You need:

A modern web browser

Internet access for GeoIP enrichment

Clone the Repository

git clone https://github.com/Shriniketan369/mail_forensix.git
cd mail_forensix

Run Locally

The simplest option is to open:

index.html

directly in a browser.

For local development, a static HTTP server is recommended.

Python

python -m http.server 8000

Open:

http://localhost:8000

Usage

Launch the application.

Paste a raw email into the analysis interface.

Start the analysis.

Review the parsed email information.

Inspect authentication and phishing indicators.

Review the ML/text-analysis signal.

Inspect sender IP and GeoIP enrichment where available.

Review the final verdict and confidence.

Read the generated reasoning and red flags.

Follow the recommended action or copy the forensic report.

The application also includes sample emails for demonstration and testing.

Technology Stack

Technology

Purpose

HTML5

Application structure

CSS3

Interface and responsive styling

Vanilla JavaScript

Application logic

JavaScript Regex / Rules

Email and phishing detection

Client-side ML/Text Analysis

Suspicious-language scoring

GeoIP API

Sender IP enrichment

Browser APIs

Local client-side workflow

No heavy backend framework is required for the current architecture.

Security & Privacy

Mail ForensiX is designed as a defensive analysis tool.

Important considerations

Email analysis is primarily performed client-side.

GeoIP enrichment requires a network request for the sender IP.

Do not submit confidential or regulated email content to an untrusted public deployment.

GeoIP information is approximate and should not be interpreted as proof of a person's physical location.

VPNs, proxies, cloud infrastructure, NAT, mail gateways, and relays can make IP geolocation differ from the actual sender's location.

A single detection signal should never be treated as conclusive evidence.

For production environments, consider adding a dedicated backend, access control, audit logging, privacy controls, and enterprise-grade threat-intelligence providers.

Limitations

Mail ForensiX is a forensic analysis prototype, not a replacement for a production email security gateway.

Potential limitations include:

Header information can be incomplete or manipulated.

SPF/DKIM/DMARC results may not always provide a complete picture.

Legitimate third-party mail services can create unusual authentication or routing patterns.

Language-based detection can produce false positives.

Novel phishing campaigns may evade static rules.

IP geolocation is inherently approximate.

Brand/domain matching currently relies on a finite set of known brands.

The client-side architecture is not intended for large-scale enterprise mail processing.

Use the generated verdict as decision support, not as absolute proof.

Roadmap

Potential future enhancements include:

.eml file upload and automated parsing

Attachment metadata and malware analysis

URL reputation checks

Domain reputation and age analysis

DNS / MX / SPF record inspection

Expanded brand impersonation detection

Threat-intelligence integrations

VirusTotal / URLScan enrichment

IOC extraction

PDF / JSON report export

Case management

Persistent investigation history

Email campaign clustering

Authentication-chain visualization

Advanced NLP / transformer-based classification

SIEM / SOC integrations

API-based enterprise deployment

Responsible Use

Mail ForensiX is intended for:

Defensive cybersecurity

Email security analysis

Phishing investigation

Digital forensics education

SOC training

Security research

Authorized incident response

Cybersecurity competitions and demonstrations

Only analyze emails and network information that you are authorized to investigate.

Contributing

Contributions are welcome.

Development workflow

git clone https://github.com/Shriniketan369/mail_forensix.git
cd mail_forensix

git checkout -b feature/your-feature

Make your changes, test them locally, and submit a pull request.

When contributing, please include:

A clear description of the change

The motivation behind it

Testing performed

Any security or privacy considerations

License

No open-source license is currently specified in the repository.

If this project is intended for public distribution or external contributions, adding a license such as MIT, Apache-2.0, or GPL-3.0 is recommended.

Project

Repository:
https://github.com/Shriniketan369/mail_forensix

Author:
Shriniketan369

Core Principle

<p align="center">
  <strong>Every flag is auditable. No black box.</strong>
</p>

<p align="center">
  Mail ForensiX turns raw email evidence into an explainable security verdict.
</p>

<p align="center">
  Built for cybersecurity analysis, education, and defensive security.
</p>
