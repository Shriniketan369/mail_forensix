<h1 align="center">Mail ForensiX</h1>

<p align="center">
  Paste a raw email. Get a forensic report and a clear verdict.<br>
  Everything runs in your browser.
</p>

<p align="center">
  <a href="https://shriniketan369.github.io/mail_forensix/">Live demo</a> &nbsp;|&nbsp;
  <a href="#getting-started">Getting started</a> &nbsp;|&nbsp;
  <a href="#how-it-works">How it works</a> &nbsp;|&nbsp;
  <a href="#limitations">Limitations</a>
</p>

<!-- Add a screenshot of a report, then remove this line and the closing arrow below:
<p align="center">
  <img src="assets/screenshot.png" alt="Mail ForensiX report" width="720">
</p>
-->

## What it does

Mail ForensiX analyzes the raw source of an email (headers and body) to detect phishing and other malicious mail. It combines a transparent, rule-based scoring engine with a small offline machine learning classifier, then shows the result as a detailed report.

There is no backend, no API key, and no email content leaves your machine. The one optional exception is the sender IP lookup, explained in [Privacy](#privacy).

## Features

- **Raw email parsing:** extracts headers, body, sender IP and the full `Received:` chain
- **Authentication checks:** reads SPF, DKIM and DMARC results from the `Authentication-Results` header
- **Rule-based risk score:** an auditable, weighted rubric (see below)
- **ML text classifier:** a Multinomial Naive Bayes model, trained offline, scores the body text on its own and shows the words that influenced the score
- **Sender geolocation:** approximate location and ISP of the originating IP
- **Clear verdict:** Safe, Suspicious or Malicious, with a confidence score, a plain-language explanation, a recommended action and a breakdown of every signal
- **Session history:** tracks every email analyzed in the session and summarizes the verdicts
- **Sample emails:** built-in legitimate and phishing examples to try

### What the rules check

| Signal | Examples |
| --- | --- |
| Authentication | Failed SPF, DKIM or DMARC |
| Sender identity | `From` and `Reply-To` domain mismatch; sender domain does not match the claimed brand |
| Pressure language | "act now", "within 24 hours" |
| Threats | Account suspension, legal action |
| Sensitive requests | Passwords, OTPs, card or PIN numbers |
| Links | Non-HTTPS links, URL shorteners, raw-IP links |
| Greeting | Generic, non-personalized greetings |

## How it works

1. **Parse** (`parser.js`): splits the email into headers and body, finds the sender IP in the `Received` chain, and reads the SPF, DKIM and DMARC results.
2. **Rule score** (`classifier.js`): each triggered rule adds points to a 0 to 100 risk score.
3. **ML score** (`ml.js`): the Naive Bayes model scores the body text separately.
4. **Fuse:** the final score is 60% rule-based and 40% ML.
5. **Locate** (`geoip.js`): looks up the sender IP for approximate origin and ISP.
6. **Report** (`app.js`, `index.html`): shows tabs for Overview, Authentication, Headers, URLs and Geolocation.

| Final score | Verdict |
| --- | --- |
| 0 to 25 | Safe |
| 26 to 55 | Suspicious |
| 56 to 100 | Malicious |

## Getting started

No build step and no dependencies.

1. Clone or download this repository.
2. Open `index.html` in a browser, or use the [live demo](https://shriniketan369.github.io/mail_forensix/).
3. Paste the full raw source of an email, including headers like `From`, `Received` and `Authentication-Results`. Or click **Load legitimate sample** or **Load phishing sample**.
4. Click **Analyze email**.

> **Tip:** most email clients can show the raw message. In Gmail, use **Show original**. In Outlook, use **View message source**. Paste that full text, not just the visible body.

## Project structure

```
.
├── index.html      App shell and report UI
├── styles.css      Styling
├── parser.js       Raw email to headers, body, sender IP, auth results
├── classifier.js   Rule-based scoring and score fusion
├── ml.js           Offline Naive Bayes text classifier
├── geoip.js        Sender IP geolocation lookup
├── app.js          App logic, UI wiring, samples, history and stats
└── logo.png        App icon
```

## Privacy

Parsing and classification run fully offline, and no email content is sent anywhere.

The one exception is geolocation. The extracted sender IP address is sent to [ipapi.co](https://ipapi.co), a free HTTPS service that needs no API key. Private and internal IP addresses are detected and skipped. For a fully air-gapped setup, remove or disable the lookup in `geoip.js`.

## Limitations

- The result is a heuristic risk assessment, not a definitive verdict. Use it to assist manual review, not replace it.
- The ML classifier is trained on a small, illustrative dataset. It complements the rule-based signals and does not replace them.
- Header parsing expects reasonably well-formed RFC 5322 email. Heavily malformed or obfuscated headers may not parse correctly.
- Geolocation depends on a third-party provider and is approximate, typically city or region level at best.

## Disclaimer

Mail ForensiX is for educational and defensive security use, on emails you have legitimate access to, such as your own inbox or a security team's investigation queue. Verify suspicious emails through official channels before acting, and report confirmed phishing to your organization's IT or security team.
