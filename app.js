// ============================================================
// APP LOGIC - ties together parser.js, classifier.js, geoip.js
// ============================================================

const SAMPLE_PHISHING = `Delivered-To: victim@gmail.com
Received: by 2002:a05:7 with SMTP id abc123;
        Fri, 11 Sep 2026 03:15:22 -0700 (PDT)
Received: from mail.suspicious-domain.ru ([185.220.101.47])
        by mx.google.com with ESMTP id xyz789
        for <victim@gmail.com>;
        Fri, 11 Sep 2026 03:15:20 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=fail smtp.mailfrom=alerts@suspicious-domain.ru;
       dkim=fail;
       dmarc=fail
From: "SBI Bank Security" <security@sbi-verify.com>
Reply-To: recovery-support@totally-legit-bank.ru
To: victim@gmail.com
Subject: URGENT: Your Account Will Be Suspended in 24 Hours!
Date: Fri, 11 Sep 2026 10:15:18 +0000
Content-Type: text/plain

Dear Customer,

We have detected unusual activity on your SBI account. Your account
will be SUSPENDED within 24 hours unless you verify your identity
immediately.

Click here to verify: http://sbi-verify-secure.ru/login

Failure to act will result in permanent account closure.

SBI Security Team`;

const SAMPLE_LEGIT = `Delivered-To: you@gmail.com
Received: by 2002:a05:7 with SMTP id def456;
        Fri, 11 Sep 2026 09:02:11 -0700 (PDT)
Received: from mail-out.github.com ([140.82.113.22])
        by mx.google.com with ESMTPS id gh789
        for <you@gmail.com>;
        Fri, 11 Sep 2026 09:02:09 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=pass smtp.mailfrom=notifications@github.com;
       dkim=pass;
       dmarc=pass
From: "GitHub" <notifications@github.com>
Reply-To: notifications@github.com
To: you@gmail.com
Subject: [your-repo] New pull request opened by teammate
Date: Fri, 11 Sep 2026 16:02:05 +0000
Content-Type: text/plain

Hi there,

teammate opened a new pull request in your-org/your-repo:

"Fix header parsing edge case for multiline Received headers"

View it here: https://github.com/your-org/your-repo/pull/42

Thanks,
The GitHub Team`;

let currentReportData = null;

document.getElementById('sampleLegit').addEventListener('click', () => {
  document.getElementById('emailInput').value = SAMPLE_LEGIT;
});

document.getElementById('samplePhishing').addEventListener('click', () => {
  document.getElementById('emailInput').value = SAMPLE_PHISHING;
});

document.getElementById('analyzeBtn').addEventListener('click', runAnalysis);

async function runAnalysis() {
  const rawEmail = document.getElementById('emailInput').value.trim();
  const statusEl = document.getElementById('statusLine');
  const analyzeBtn = document.getElementById('analyzeBtn');

  statusEl.className = 'status-line';
  statusEl.textContent = '';

  if (!rawEmail) {
    statusEl.className = 'status-line error';
    statusEl.textContent = 'Paste an email first, or load a sample.';
    return;
  }

  analyzeBtn.disabled = true;
  document.getElementById('report').classList.remove('visible');

  try {
    statusEl.textContent = '> parsing headers...';
    const parsed = parseEmail(rawEmail);
    await sleep(200); // tiny delay so the status line is readable in a live demo

    statusEl.textContent = '> scoring against detection rubric...';
    const classification = await classifyEmail(parsed);

    statusEl.textContent = '> tracing sender IP geolocation...';
    const geo = await geoLookup(parsed.senderIP);

    statusEl.textContent = '> compiling forensic report...';
    await sleep(150);

    currentReportData = { parsed, classification, geo };
    renderReport(currentReportData);

    statusEl.textContent = '';
  } catch (err) {
    statusEl.className = 'status-line error';
    statusEl.textContent = 'Error: ' + err.message;
  } finally {
    analyzeBtn.disabled = false;
  }
}

function renderReport({ parsed, classification, geo }) {
  const report = document.getElementById('report');
  const verdict = classification.verdict || 'Suspicious';

  document.getElementById('verdictBanner').className = `verdict-banner ${verdict}`;
  document.getElementById('verdictLabel').className = `verdict-label ${verdict}`;
  document.getElementById('verdictLabel').textContent = verdict.toUpperCase();
  document.getElementById('confidence').textContent = `${classification.confidence}% confidence`;
  document.getElementById('reasoning').textContent = classification.reasoning || '';

  const flagsEl = document.getElementById('redFlags');
  flagsEl.innerHTML = '';
  (classification.redFlags || []).forEach(flag => {
    const tag = document.createElement('span');
    tag.className = 'red-flag-tag';
    tag.textContent = flag;
    flagsEl.appendChild(tag);
  });

  document.getElementById('recommendedAction').innerHTML =
    `<b>Recommended action:</b> ${classification.recommendedAction || 'Review manually.'}`;

  // Header forensics
  document.getElementById('fFrom').textContent = parsed.from || '—';
  document.getElementById('fReplyTo').textContent = parsed.replyTo || '(not set)';
  document.getElementById('fSubject').textContent = parsed.subject || '—';
  document.getElementById('fMismatch').textContent = parsed.fromReplyToMismatch ? 'Yes ⚠️' : 'No';

  renderAuthPill('fSpf', parsed.spf);
  renderAuthPill('fDkim', parsed.dkim);
  renderAuthPill('fDmarc', parsed.dmarc);

  // GeoIP
  const geoBox = document.getElementById('geoBox');
  if (geo.error) {
    geoBox.innerHTML = `<div class="geo-error">${geo.error}</div>`;
  } else if (geo.isPrivate) {
    geoBox.innerHTML = `<div class="geo-error">${geo.note}</div>`;
  } else {
    geoBox.innerHTML = `
      <dl class="kv-grid">
        <dt>Sender IP</dt><dd>${geo.ip}</dd>
        <dt>Location</dt><dd>${geo.city || '?'}, ${geo.region || '?'}, ${geo.country || '?'}</dd>
        <dt>ISP / Org</dt><dd>${geo.isp || 'unknown'}</dd>
        <dt>Timezone</dt><dd>${geo.timezone || 'unknown'}</dd>
      </dl>`;
  }

  report.classList.add('visible');
  report.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderAuthPill(elId, value) {
  const el = document.getElementById(elId);
  el.textContent = value.toUpperCase();
  el.className = 'auth-pill ' + (value === 'pass' ? 'pass' : value === 'fail' ? 'fail' : 'unknown');
}

document.getElementById('copyReport').addEventListener('click', () => {
  if (!currentReportData) return;
  const { parsed, classification, geo } = currentReportData;
  const text = `EMAIL FORENSIC REPORT
======================
Verdict: ${classification.verdict} (${classification.confidence}% confidence)
Reasoning: ${classification.reasoning}
Red flags: ${(classification.redFlags || []).join(', ')}
Recommended action: ${classification.recommendedAction}

From: ${parsed.from}
Reply-To: ${parsed.replyTo || '(not set)'}
Subject: ${parsed.subject}
SPF: ${parsed.spf} | DKIM: ${parsed.dkim} | DMARC: ${parsed.dmarc}

Sender IP: ${parsed.senderIP || 'unknown'}
Geolocation: ${geo.city || '?'}, ${geo.region || '?'}, ${geo.country || '?'}
ISP: ${geo.isp || 'unknown'}
`;
  navigator.clipboard.writeText(text);
  const btn = document.getElementById('copyReport');
  const original = btn.textContent;
  btn.textContent = 'Copied ✓';
  setTimeout(() => (btn.textContent = original), 1500);
});

function sleep(ms) { return new Promise(res => setTimeout(res, ms)); }
