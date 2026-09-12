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
let reportCounter = 10290;
const analysisHistory = []; // { id, timestamp, parsed, classification, geo }

// ---------------- View switching ----------------
document.querySelectorAll('.rail-item').forEach((btn) => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

// ---------------- Report tab switching ----------------
document.getElementById('tabsNav').addEventListener('click', (e) => {
  const btn = e.target.closest('.tab-btn');
  if (!btn) return;
  switchTab(btn.dataset.tab);
});

function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.tab-pane').forEach((p) => p.classList.toggle('active', p.id === `tab-${tab}`));
  document.querySelector('.tabs-panel')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

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
document.getElementById('newAnalysisBtn').addEventListener('click', () => {
  document.getElementById('report').classList.remove('visible');
  document.getElementById('emptyState').style.display = 'flex';
  document.getElementById('pipelinePanel').hidden = true;
  document.getElementById('emailInput').focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// ---------------- Pipeline stepper ----------------
const PIPELINE_STAGES = [
  { id: 'parse', label: 'Parsing headers' },
  { id: 'body', label: 'Extracting body' },
  { id: 'spf', label: 'Checking SPF' },
  { id: 'dkim', label: 'Checking DKIM' },
  { id: 'dmarc', label: 'Checking DMARC' },
  { id: 'urls', label: 'Scanning URLs' },
  { id: 'ml', label: 'Scoring wording (ML)' },
  { id: 'geo', label: 'Tracing sender IP' },
  { id: 'risk', label: 'Calculating risk' },
];

function initPipeline() {
  const panel = document.getElementById('pipelinePanel');
  const stepsEl = document.getElementById('pipelineSteps');
  const statusEl = document.getElementById('pipelineStatus');
  panel.hidden = false;
  statusEl.textContent = 'Running…';
  statusEl.classList.remove('done');
  stepsEl.innerHTML = PIPELINE_STAGES.map((s) => `
    <div class="pipeline-step" data-stage="${s.id}">
      <div class="pipeline-dot">${DONE_CHECK}</div>
      <div class="pipeline-label">${s.label}</div>
      <div class="pipeline-time">—</div>
    </div>`).join('');
  // reset dot content to a neutral dash until active/done
  stepsEl.querySelectorAll('.pipeline-dot').forEach((d) => (d.innerHTML = ''));
}

const DONE_CHECK = '<svg viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function setStage(stageId, state, elapsedMs) {
  const stepEl = document.querySelector(`.pipeline-step[data-stage="${stageId}"]`);
  if (!stepEl) return;
  stepEl.classList.remove('active', 'done');
  stepEl.classList.add(state);
  const dot = stepEl.querySelector('.pipeline-dot');
  const timeEl = stepEl.querySelector('.pipeline-time');
  dot.innerHTML = state === 'done' ? DONE_CHECK : '';
  if (state === 'done' && typeof elapsedMs === 'number') {
    timeEl.textContent = `${(elapsedMs / 1000).toFixed(1)}s`;
  }
}

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

  const t0 = performance.now();
  const elapsed = () => performance.now() - t0;

  try {
    initPipeline();

    setStage('parse', 'active');
    await sleep(90);
    const parsed = parseEmail(rawEmail);
    setStage('parse', 'done', elapsed());

    setStage('body', 'active');
    await sleep(70);
    setStage('body', 'done', elapsed());

    setStage('spf', 'active');
    await sleep(90);
    setStage('spf', 'done', elapsed());

    setStage('dkim', 'active');
    await sleep(90);
    setStage('dkim', 'done', elapsed());

    setStage('dmarc', 'active');
    await sleep(90);
    setStage('dmarc', 'done', elapsed());

    setStage('urls', 'active');
    await sleep(110);
    setStage('urls', 'done', elapsed());

    setStage('ml', 'active');
    await sleep(120);
    const classification = await classifyEmail(parsed);
    setStage('ml', 'done', elapsed());

    setStage('geo', 'active');
    const geo = await geoLookup(parsed.senderIP);
    setStage('geo', 'done', elapsed());

    setStage('risk', 'active');
    await sleep(80);
    setStage('risk', 'done', elapsed());

    document.getElementById('pipelineStatus').textContent = 'Complete';
    document.getElementById('pipelineStatus').classList.add('done');

    reportCounter += 1;
    currentReportData = { parsed, classification, geo, reportId: `MF-${reportCounter}`, analyzedAt: new Date() };
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

const VERDICT_RISK_LABEL = { Safe: 'Low risk', Suspicious: 'Needs review', Malicious: 'High risk' };
const VERDICT_HEADLINE = { Safe: 'Looks safe', Suspicious: 'Possibly suspicious', Malicious: 'Likely phishing' };

// Short, plain-language explanations for the "Why?" toggle on flagged indicators.
const RULE_EXPLANATIONS = {
  spf_fail: 'SPF lets a domain publish which mail servers are allowed to send on its behalf. A failure means the sending server was not on that list — a strong sign the From address was spoofed.',
  dkim_fail: "DKIM is a cryptographic signature the real domain attaches to outgoing mail. A failure means the message either wasn't signed by the claimed domain or was altered in transit.",
  dmarc_fail: 'DMARC ties SPF and DKIM back to the visible From domain. A failure means the message could not be verified as actually coming from that domain.',
  reply_to_mismatch: 'Replies would go to a different domain than the one the message claims to be from — a common trick so responses skip the real organization entirely.',
  urgency_language: 'Phrases pushing you to act "immediately" or "within 24 hours" are a classic social-engineering tactic to short-circuit careful thinking.',
  threat_language: 'Threats of suspension, closure, or legal action are used to pressure recipients into acting before they verify anything.',
  sensitive_info_request: 'The message asks for a password, OTP, card number, or similar — information no legitimate service should ask you to send by email.',
  suspicious_link: 'At least one link uses a non-HTTPS address, a raw IP, a URL shortener, or a deceptive keyword pattern often used to disguise a phishing destination.',
  brand_domain_mismatch: "The email invokes a well-known brand, but the sender's actual domain doesn't match that brand's real domain.",
  generic_greeting: 'A generic greeting like "Dear Customer" suggests a mass campaign rather than a message personalized by an organization that already knows your name.',
  ml_wording: 'Independently of the rules above, the statistical text classifier recognized this wording pattern from its training on labeled phishing and legitimate emails.',
};

const RING_CIRCUMFERENCE = 2 * Math.PI * 44;

// Groups of RUBRIC rule ids used to build the category-level risk breakdown.
// Maximums are derived from the actual rule weights in classifier.js, so the
// bars always reflect the real scoring model rather than invented numbers.
const RISK_CATEGORIES = [
  { key: 'cat-auth', label: 'Authentication (SPF/DKIM/DMARC)', ids: ['spf_fail', 'dkim_fail', 'dmarc_fail'] },
  { key: 'cat-identity', label: 'Sender identity', ids: ['reply_to_mismatch', 'brand_domain_mismatch'] },
  { key: 'cat-content', label: 'Content & language', ids: ['urgency_language', 'threat_language', 'sensitive_info_request', 'generic_greeting'] },
  { key: 'cat-links', label: 'Links', ids: ['suspicious_link'] },
];

function renderReport({ parsed, classification, geo, reportId, analyzedAt }) {
  const report = document.getElementById('report');
  const verdict = classification.verdict || 'Suspicious';
  const score = typeof classification._score === 'number' ? classification._score : classification._rubricScore;
  const flagged = classification.flaggedIndicators || [];

  // Report header
  document.getElementById('reportId').textContent = `Analysis #${reportId}`;
  document.getElementById('reportMeta').textContent = `${analyzedAt.toLocaleDateString()} · ${analyzedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;

  // Score ring
  const ringFill = document.getElementById('ringFill');
  ringFill.setAttribute('stroke-dasharray', `${RING_CIRCUMFERENCE}`);
  const offset = RING_CIRCUMFERENCE * (1 - Math.min(100, Math.max(0, score)) / 100);
  ringFill.setAttribute('stroke-dashoffset', `${offset}`);
  ringFill.setAttribute('class', `ring-fill ${verdict}`);
  document.getElementById('ringScore').textContent = score;

  document.getElementById('verdictBadge').className = `verdict-badge ${verdict}`;
  document.getElementById('verdictBadgeLabel').textContent = VERDICT_RISK_LABEL[verdict] || verdict;
  document.getElementById('verdictIcon').className = `verdict-icon ${verdict}`;
  document.getElementById('verdictIcon').innerHTML = VERDICT_ICONS[verdict] || VERDICT_ICONS.Suspicious;
  document.getElementById('verdictLabel').className = `verdict-label ${verdict}`;
  document.getElementById('verdictLabel').textContent = `${VERDICT_HEADLINE[verdict] || verdict} · ${flagged.length} indicator${flagged.length === 1 ? '' : 's'} contributed`;
  document.getElementById('confidence').textContent = `${classification.confidence}%`;
  document.getElementById('reasoning').textContent = classification.reasoning || '';

  const confFill = document.getElementById('confidenceFill');
  confFill.style.width = `${Math.min(100, Math.max(0, classification.confidence))}%`;
  confFill.style.background = verdict === 'Malicious' ? 'var(--malicious)' : verdict === 'Suspicious' ? 'var(--suspicious)' : 'var(--safe)';

  // Quick summary
  document.getElementById('qsFrom').textContent = parsed.from || '—';
  document.getElementById('qsTo').textContent = parsed.to || '—';
  document.getElementById('qsSubject').textContent = parsed.subject || '—';
  document.getElementById('qsDate').textContent = parsed.date || '—';

  // ---- Category risk breakdown ----
  const breakdownEl = document.getElementById('signalBreakdown');
  const rows = [];
  RISK_CATEGORIES.forEach((cat) => {
    const rules = RUBRIC.filter((r) => cat.ids.includes(r.id));
    const max = rules.reduce((s, r) => s + r.weight, 0);
    const got = flagged.filter((f) => cat.ids.includes(f.id)).reduce((s, f) => s + f.weight, 0);
    const pct = max > 0 ? Math.round((got / max) * 100) : 0;
    rows.push(`
      <div class="signal-row">
        <span class="signal-label">${cat.label}</span>
        <div class="signal-bar"><div class="signal-bar-fill ${cat.key}${got === 0 ? ' zero' : ''}" style="width:${pct}%"></div></div>
        <span class="signal-value">${got}/${max}</span>
      </div>`);
  });
  if (typeof classification._mlScore === 'number') {
    const mlScore = Math.round(classification._mlScore);
    rows.push(`
      <div class="signal-row">
        <span class="signal-label">ML text classifier</span>
        <div class="signal-bar"><div class="signal-bar-fill cat-ml${mlScore === 0 ? ' zero' : ''}" style="width:${mlScore}%"></div></div>
        <span class="signal-value">${mlScore}/100</span>
      </div>`);
  }
  breakdownEl.innerHTML = rows.join('');

  // ---- Why was this flagged (with weights + Why? toggle) ----
  const flagsEl = document.getElementById('redFlags');
  flagsEl.innerHTML = '';
  if (flagged.length === 0) {
    flagsEl.innerHTML = '<div class="no-flags">No indicators were triggered.</div>';
  } else {
    flagged
      .slice()
      .sort((a, b) => b.weight - a.weight)
      .forEach((f, i) => {
        const rowId = `flagrow-${i}`;
        const row = document.createElement('div');
        row.innerHTML = `
          <div class="flag-row">
            <span class="flag-row-icon">${WARN_ICON}</span>
            <span class="flag-row-label">${escapeHtml(f.label)}</span>
            <span class="flag-row-weight">+${f.weight}</span>
            <button class="flag-row-why" data-target="${rowId}">Why?</button>
          </div>
          <div class="flag-row-explain" id="${rowId}">${escapeHtml(RULE_EXPLANATIONS[f.id] || 'This pattern is one of the indicators the rule engine checks for.')}</div>`;
        flagsEl.appendChild(row);
      });
    flagsEl.querySelectorAll('.flag-row-why').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.getElementById(btn.dataset.target).classList.toggle('open');
      });
    });
  }

  document.getElementById('recommendedAction').innerHTML =
    `<b>Recommended action:</b> ${classification.recommendedAction || 'Review manually.'}`;

  // ---- Key indicators ----
  const urls = typeof extractUrls === 'function' ? extractUrls(parsed.body) : [];
  const suspiciousUrlCount = urls.filter((u) => u.suspicious).length;
  const authFailCount = ['spf', 'dkim', 'dmarc'].filter((k) => parsed[k] === 'fail').length;
  const kiEl = document.getElementById('keyIndicators');
  const kiRows = [
    { icon: LINK_ICON, label: 'Suspicious URLs', value: suspiciousUrlCount, tab: 'urls' },
    { icon: SHIELD_ICON, label: 'Auth checks failed', value: `${authFailCount}/3`, tab: 'auth' },
    { icon: FLAG_ICON, label: 'Rule indicators triggered', value: flagged.length, tab: 'overview' },
    { icon: PIN_ICON, label: 'Sender geolocation', value: geo.isPrivate ? 'Private IP' : geo.error ? 'Unavailable' : (geo.country || 'Unknown'), tab: 'geo' },
  ];
  kiEl.innerHTML = kiRows.map((r) => `
    <button class="ki-row" data-tab="${r.tab}">
      <span class="ki-icon">${r.icon}</span>
      <span class="ki-label">${r.label}</span>
      <span class="ki-value${(typeof r.value === 'number' && r.value > 0) ? ' flagged' : ''}">${r.value}</span>
      <svg class="ki-chev" viewBox="0 0 24 24" fill="none"><path d="M9 6l6 6-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </button>`).join('');
  kiEl.querySelectorAll('.ki-row').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // ---- Raw headers ----
  const rawHeadersEl = document.getElementById('rawHeaders');
  const headerLines = Object.entries(parsed.headers || {}).map(([k, v]) => {
    const val = Array.isArray(v) ? v.join('\n  ') : v;
    return `${k}: ${val}`;
  });
  rawHeadersEl.textContent = headerLines.length ? headerLines.join('\n') : 'No headers parsed.';

  // ---- Message route ----
  const routeEl = document.getElementById('messageRoute');
  const hops = [];
  hops.push({ kind: 'endpoint', title: parsed.from || 'Unknown sender', sub: parsed.senderIP ? `IP: ${parsed.senderIP}` : null, tag: parsed.fromReplyToMismatch ? 'Reply-To mismatch' : null });
  (parsed.receivedChain || []).slice(0, 3).forEach((hop) => {
    hops.push({ kind: 'hop', title: 'Mail relay', sub: hop, tag: null });
  });
  hops.push({ kind: 'endpoint', title: parsed.to || 'Unknown recipient', sub: null, tag: null });
  routeEl.innerHTML = hops.map((h, i) => `
    <div class="route-hop">
      <div class="route-hop-rail">
        <div class="route-hop-dot ${h.kind}${h.tag ? ' flagged' : ''}">${h.kind === 'endpoint' ? MAIL_ICON : SERVER_ICON}</div>
        ${i < hops.length - 1 ? '<div class="route-hop-line"></div>' : ''}
      </div>
      <div class="route-hop-body">
        <div class="route-hop-title">${escapeHtml(h.title)}</div>
        ${h.sub ? `<div class="route-hop-sub">${escapeHtml(h.sub)}</div>` : ''}
        ${h.tag ? `<span class="route-hop-tag">${escapeHtml(h.tag)}</span>` : ''}
      </div>
    </div>`).join('');

  document.getElementById('fFrom').textContent = parsed.from || '—';
  document.getElementById('fReplyTo').textContent = parsed.replyTo || '(not set)';
  document.getElementById('fSubject').textContent = parsed.subject || '—';
  document.getElementById('fMismatch').textContent = parsed.fromReplyToMismatch ? 'Yes ⚠️' : 'No';

  // Authentication tab
  const authCardsEl = document.getElementById('authCards');
  const authInfo = [
    { id: 'SPF', value: parsed.spf, desc: 'Verifies the sending server is authorized to send mail for this domain.' },
    { id: 'DKIM', value: parsed.dkim, desc: 'Verifies the message was signed by the claimed sending domain.' },
    { id: 'DMARC', value: parsed.dmarc, desc: 'Verifies SPF/DKIM alignment with the visible From domain.' },
  ];
  authCardsEl.innerHTML = authInfo.map((a) => `
    <div class="auth-detail-card">
      <div class="auth-detail-top">
        <span class="auth-detail-name">${a.id}</span>
        <span class="auth-pill ${a.value === 'pass' ? 'pass' : a.value === 'fail' ? 'fail' : 'unknown'}">${a.value.toUpperCase()}</span>
      </div>
      <p class="auth-detail-desc">${a.desc}</p>
    </div>`).join('');

  // Headers tab - received chain
  const chainEl = document.getElementById('receivedChain');
  if (parsed.receivedChain && parsed.receivedChain.length > 0) {
    chainEl.innerHTML = parsed.receivedChain.map((hop, i) => `
      <div class="chain-hop">
        <span class="chain-hop-index">${i + 1}</span>
        <span class="chain-hop-text">${escapeHtml(hop)}</span>
      </div>`).join('');
  } else {
    chainEl.innerHTML = '<div class="no-flags">No Received headers found.</div>';
  }

  // URLs tab
  const urlListEl = document.getElementById('urlList');
  if (urls.length === 0) {
    urlListEl.innerHTML = '<div class="no-flags">No URLs found in the email body.</div>';
  } else {
    urlListEl.innerHTML = urls.map((u) => `
      <div class="url-item ${u.suspicious ? 'suspicious' : 'safe'}">
        <div class="url-item-top">
          <span class="url-item-text">${escapeHtml(u.url)}</span>
          <span class="url-item-tag ${u.suspicious ? 'suspicious' : 'safe'}">${u.suspicious ? 'Suspicious' : 'No issues'}</span>
        </div>
        ${u.reasons.length > 0 ? `<div class="url-item-reasons">${u.reasons.join(' · ')}</div>` : ''}
      </div>`).join('');
  }

  switchTab('overview');

  // Geo (both mini panel + full tab)
  const geoBox = document.getElementById('geoBox');
  const geoMiniBox = document.getElementById('geoMiniBox');
  let geoHtml;
  if (geo.error) {
    geoHtml = `<div class="geo-error">${escapeHtml(geo.error)}</div>`;
  } else if (geo.isPrivate) {
    geoHtml = `<div class="geo-error">${escapeHtml(geo.note)}</div>`;
  } else {
    geoHtml = `
      <dl class="kv-grid">
        <dt>Sender IP</dt><dd>${escapeHtml(geo.ip)}</dd>
        <dt>Location</dt><dd>${escapeHtml(geo.city || '?')}, ${escapeHtml(geo.region || '?')}, ${escapeHtml(geo.country || '?')}</dd>
        <dt>ISP / Org</dt><dd>${escapeHtml(geo.isp || 'unknown')}</dd>
        <dt>Timezone</dt><dd>${escapeHtml(geo.timezone || 'unknown')}</dd>
      </dl>`;
  }
  geoBox.innerHTML = geoHtml;
  geoMiniBox.innerHTML = geoHtml;

  report.classList.add('visible');
  document.getElementById('emptyState').style.display = 'none';
  report.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---------------- Small inline icon set ----------------
const WARN_ICON = '<svg viewBox="0 0 24 24" fill="none"><path d="M12 9v4M12 17h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/></svg>';
const LINK_ICON = '<svg viewBox="0 0 24 24" fill="none"><path d="M9 15l6-6M10 7l1.5-1.5a3.5 3.5 0 015 5L15 12M14 17l-1.5 1.5a3.5 3.5 0 01-5-5L9 12" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const SHIELD_ICON = '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>';
const FLAG_ICON = '<svg viewBox="0 0 24 24" fill="none"><path d="M5 21V4M5 4h13l-3 4 3 4H5" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>';
const PIN_ICON = '<svg viewBox="0 0 24 24" fill="none"><path d="M12 21s7-6.5 7-11.5A7 7 0 105 9.5C5 14.5 12 21 12 21z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><circle cx="12" cy="9.5" r="2.3" stroke="currentColor" stroke-width="1.6"/></svg>';
const MAIL_ICON = '<svg viewBox="0 0 24 24" fill="none"><rect x="3" y="5" width="18" height="14" rx="2" stroke="currentColor" stroke-width="1.6"/><path d="M3 7l9 6 9-6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const SERVER_ICON = '<svg viewBox="0 0 24 24" fill="none"><rect x="4" y="4" width="16" height="6" rx="1.5" stroke="currentColor" stroke-width="1.6"/><rect x="4" y="14" width="16" height="6" rx="1.5" stroke="currentColor" stroke-width="1.6"/><circle cx="8" cy="7" r="0.8" fill="currentColor"/><circle cx="8" cy="17" r="0.8" fill="currentColor"/></svg>';

function copyReportToClipboard() {
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
}

function flashCopied(btn) {
  const original = btn.innerHTML;
  btn.textContent = 'Copied ✓';
  setTimeout(() => (btn.innerHTML = original), 1500);
}

document.getElementById('copyReport').addEventListener('click', (e) => { copyReportToClipboard(); flashCopied(e.currentTarget); });
document.getElementById('copyReport2').addEventListener('click', (e) => { copyReportToClipboard(); flashCopied(e.currentTarget); });

// ---------------- History ----------------
function addToHistory(entry) {
  analysisHistory.unshift({ ...entry, timestamp: entry.analyzedAt || new Date() });
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

  listEl.innerHTML = analysisHistory.map((entry, idx) => {
    const v = entry.classification.verdict;
    const time = entry.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `
      <div class="history-item" data-idx="${idx}">
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
      const entry = analysisHistory[Number(item.dataset.idx)];
      if (!entry) return;
      currentReportData = entry;
      switchView('analyze');
      document.getElementById('pipelinePanel').hidden = true;
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
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

function sleep(ms) { return new Promise(res => setTimeout(res, ms)); }
