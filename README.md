Mail ForensiX

Mail ForensiX is a client-side email forensics tool that analyzes raw email source (headers + body) to detect phishing and other malicious mail. It combines a transparent, rule-based scoring engine with a lightweight offline machine learning classifier, and presents the results as a detailed forensic report — authentication status, header analysis, URL inspection, sender geolocation, and an overall risk verdict.

Everything runs entirely in the browser. There is no backend, no API key, and no email content ever leaves the user's machine (aside from an optional IP geolocation lookup — see Privacy & Network Usage).

Features
Raw email parsing — extracts headers, body, sender IP, and the full Received: chain from pasted raw email source.
Authentication checks — parses SPF, DKIM, and DMARC results from the Authentication-Results header.
Rule-based risk scoring — an auditable, weighted rubric checks for:
Failed SPF / DKIM / DMARC
From / Reply-To domain mismatches
Urgency and pressure language ("act now", "within 24 hours", etc.)
Threatening language (account suspension, legal action, etc.)
Requests for sensitive information (passwords, OTPs, card/PIN numbers, etc.)
Suspicious or non-HTTPS links, URL shorteners, and raw-IP links
Sender domain / claimed brand mismatches (e.g. an email claiming to be from a bank sent from an unrelated domain)
Generic, non-personalized greetings
ML text classifier — a Multinomial Naive Bayes model, trained offline on a labeled phishing/legitimate email corpus, scores the body text independently based on learned wording patterns. Its output is fused with the rule-based score to produce the final verdict.
Sender geolocation — resolves the originating IP address from the Received chain and looks up its approximate location and ISP.
Verdict & report — classifies each email as Safe, Suspicious, or Malicious, with a confidence score, a plain-language explanation, a recommended action, and a full breakdown of every signal that contributed to the score.
Session history & stats — tracks every email analyzed during the session and summarizes verdict distribution.
Sample emails — built-in legitimate and phishing sample messages for quickly trying out the tool.
How It Works
Parsing (parser.js) — splits the raw email into headers and body, extracts the sender IP from the Received header chain, and reads SPF/DKIM/DMARC results.
Rule-based scoring (classifier.js) — runs the parsed email through a weighted rubric of phishing indicators. Each triggered rule contributes points toward a 0–100 risk score.
ML scoring (ml.js) — independently scores the body text using a pre-trained Naive Bayes model and surfaces the words that most influenced the score.
Score fusion — the rule-based score (60%) and ML score (40%) are combined into a final risk score, which maps to a verdict:
0–25 → Safe
26–55 → Suspicious
56–100 → Malicious
Geolocation (geoip.js) — the extracted sender IP is looked up via a public GeoIP API to show approximate origin and ISP.
Report rendering (app.js, index.html) — results are displayed as an interactive report with tabs for Overview, Authentication, Headers, URLs, and Geolocation.
Getting Started

No build step or dependencies are required.

Clone or download this repository.
Open index.html in a web browser.
Paste the full raw source of an email (including headers such as From, Received, and Authentication-Results) into the input box, or click Load legitimate sample / Load phishing sample to try it out.
Click Analyze email to view the forensic report.

Tip: Most email clients let you view the raw/original message source (e.g. Gmail: "Show original"; Outlook: "View message source"). Paste that full text, not just the visible email body.

Project Structure
.
├── index.html      # App shell and report UI
├── styles.css      # Styling
├── parser.js       # Raw email → headers, body, sender IP, auth results
├── classifier.js   # Rule-based scoring rubric and score fusion
├── ml.js           # Offline Naive Bayes text classifier
├── geoip.js        # Sender IP geolocation lookup
├── app.js          # App logic, UI wiring, sample emails, history/stats
└── logo.png        # App icon/logo
Privacy & Network Usage

Mail ForensiX is designed to run fully offline for parsing and classification — no email content is ever transmitted anywhere. The one exception is sender geolocation: the extracted sender IP address is sent to ipapi.co (a free, HTTPS, no-API-key GeoIP service) to resolve an approximate location. Private/internal IP addresses are detected and skipped automatically.

If you want a fully air-gapped setup, you can disable or remove the geolocation lookup in geoip.js.

Limitations
This tool provides a heuristic risk assessment, not a definitive verdict. It is intended to assist manual review, not replace it.
The ML classifier is trained on a small, illustrative dataset and is meant to complement — not replace — the rule-based signals.
Header parsing assumes reasonably well-formed RFC 5322 email source; heavily malformed or obfuscated headers may not parse correctly.
Geolocation accuracy depends on the third-party GeoIP provider and is approximate (typically city/region level at best).

Disclaimer
Mail ForensiX is intended for educational and defensive security use — analyzing emails you have legitimate access to (e.g. your own inbox or a security team's investigation queue). Always verify suspicious emails through official channels before taking action, and report confirmed phishing to your organization's IT/security team.

mail_forensix-main.zip

ZIP
