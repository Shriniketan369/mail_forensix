// ============================================================
// APP LOGIC - ties together parser.js, classifier.js, geoip.js
// plus dashboard shell: view switching, history, stats
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
const analysisHistory = []; // { id, timestamp, parsed, classification, geo }

// ---------------- View switching ----------------
document.querySelectorAll('.rail-item').forEach((btn) => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

function switchView(view) {
  document.querySelectorAll('.rail-item').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${view}`));
  if (view === 'history') renderHistoryView();
  if (view === 'stats') renderStatsView();
}

// ---------------- Sample buttons ----------------
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
    await sleep(200);

    statusEl.textContent = '> scoring against detection rubric + ML model...';
    const classification = await classifyEmail(parsed);

    statusEl.textContent = '> tracing sender IP geolocation...';
    const geo = await geoLookup(parsed.senderIP);

    statusEl.textContent = '> compiling forensic report...';
    await sleep(150);

    currentReportData = { parsed, classification, geo };
    renderReport(currentReportData);
    addToHistory(currentReportData);

    statusEl.textContent = '';
  } catch (err) {
    statusEl.className = 'status-line error';
    statusEl.textContent = 'Error: ' + err.message;
  } finally {
    analyzeBtn.disabled = false;
  }
}

// ---------------- Verdict icons (inline SVG per verdict) ----------------
const VERDICT_ICONS = {
  Safe: '<svg viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  Suspicious: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 9v4M12 17h.01M10.29 3.86l-8.18 14A2 2 0 004 21h16a2 2 0 001.89-3.14l-8.18-14a2 2 0 00-3.42 0z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  Malicious: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 8v5M12 16h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/></svg>',
};

function renderReport({ parsed, classification, geo }) {
  const report = document.getElementById('report');
  const verdict = classification.verdict || 'Suspicious';

  document.getElementById('verdictIcon').className = `verdict-icon ${verdict}`;
  document.getElementById('verdictIcon').innerHTML = VERDICT_ICONS[verdict] || VERDICT_ICONS.Suspicious;
  document.getElementById('verdictLabel').className = `verdict-label ${verdict}`;
  document.getElementById('verdictLabel').textContent = verdict;
  document.getElementById('confidence').textContent = `${classification.confidence}%`;
  document.getElementById('reasoning').textContent = classification.reasoning || '';

  const breakdownEl = document.getElementById('signalBreakdown');
  if (typeof classification._mlScore === 'number') {
    const rubricScore = classification._rubricScore;
    const mlScore = classification._mlScore;
    const rubricZero = rubricScore === 0 ? ' zero' : '';
    const mlZero = mlScore === 0 ? ' zero' : '';
    breakdownEl.innerHTML = `
      <div class="signal-row">
        <span class="signal-label">Rule-based rubric</span>
        <div class="signal-bar"><div class="signal-bar-fill rubric${rubricZero}" style="width:${rubricScore}%"></div></div>
        <span class="signal-value">${rubricScore}%</span>
      </div>
      <div class="signal-row">
        <span class="signal-label">ML text classifier</span>
        <div class="signal-bar"><div class="signal-bar-fill ml${mlZero}" style="width:${mlScore}%"></div></div>
        <span class="signal-value">${mlScore}%</span>
      </div>`;
  } else {
    breakdownEl.innerHTML = '';
  }

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

  document.getElementById('fFrom').textContent = parsed.from || '—';
  document.getElementById('fReplyTo').textContent = parsed.replyTo || '(not set)';
  document.getElementById('fSubject').textContent = parsed.subject || '—';
  document.getElementById('fMismatch').textContent = parsed.fromReplyToMismatch ? 'Yes ⚠️' : 'No';

  renderAuthPill('fSpf', parsed.spf);
  renderAuthPill('fDkim', parsed.dkim);
  renderAuthPill('fDmarc', parsed.dmarc);

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
  document.getElementById('emptyState').style.display = 'none';
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

// ---------------- History ----------------
function addToHistory(entry) {
  analysisHistory.unshift({ ...entry, id: Date.now(), timestamp: new Date() });
  const countEl = document.getElementById('historyCount');
  countEl.hidden = analysisHistory.length === 0;
  countEl.textContent = analysisHistory.length;
}

function renderHistoryView() {
  const listEl = document.getElementById('historyList');
  const emptyEl = document.getElementById('historyEmpty');

  if (analysisHistory.length === 0) {
    listEl.innerHTML = '';
    emptyEl.style.display = 'flex';
    return;
  }
  emptyEl.style.display = 'none';

  listEl.innerHTML = analysisHistory.map((entry) => {
    const v = entry.classification.verdict;
    const time = entry.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `
      <div class="history-item" data-id="${entry.id}">
        <div class="history-dot ${v}"></div>
        <div class="history-main">
          <div class="history-subject">${escapeHtml(entry.parsed.subject || '(no subject)')}</div>
          <div class="history-from">${escapeHtml(entry.parsed.from || 'unknown sender')} · ${time}</div>
        </div>
        <div class="history-verdict ${v}">${v}</div>
      </div>`;
  }).join('');

  listEl.querySelectorAll('.history-item').forEach((item) => {
    item.addEventListener('click', () => {
      const entry = analysisHistory.find((e) => String(e.id) === item.dataset.id);
      if (!entry) return;
      currentReportData = entry;
      switchView('analyze');
      renderReport(entry);
    });
  });
}

// ---------------- Stats ----------------
function renderStatsView() {
  const total = analysisHistory.length;
  const emptyEl = document.getElementById('statsEmpty');
  const counts = { Safe: 0, Suspicious: 0, Malicious: 0 };
  analysisHistory.forEach((e) => {
    const v = e.classification.verdict;
    if (counts[v] !== undefined) counts[v]++;
  });

  document.getElementById('statTotal').textContent = total;
  document.getElementById('statSafe').textContent = counts.Safe;
  document.getElementById('statSuspicious').textContent = counts.Suspicious;
  document.getElementById('statMalicious').textContent = counts.Malicious;

  const chartEl = document.getElementById('verdictChart');
  if (total === 0) {
    chartEl.innerHTML = '';
    emptyEl.style.display = 'flex';
    return;
  }
  emptyEl.style.display = 'none';

  chartEl.innerHTML = ['Safe', 'Suspicious', 'Malicious'].map((v) => {
    const pct = total ? Math.round((counts[v] / total) * 100) : 0;
    return `
      <div class="bar-row">
        <span class="bar-row-label">${v}</span>
        <div class="bar-track"><div class="bar-fill ${v}" style="width:${pct}%"></div></div>
        <span class="bar-row-value">${counts[v]}</span>
      </div>`;
  }).join('');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function sleep(ms) { return new Promise(res => setTimeout(res, ms)); }
