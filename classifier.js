// ============================================================
// THREAT CLASSIFICATION MODULE
// Deterministic rule-based scoring engine — NO external API,
// NO API key, works fully offline. Every rule and its weight
// is listed below so the logic is auditable and explainable
// (this is also the "forensic rubric" for the pitch deck).
// ============================================================

const RUBRIC = [
  {
    id: 'spf_fail',
    weight: 20,
    test: (p) => p.spf === 'fail',
    label: 'SPF authentication failed',
  },
  {
    id: 'dkim_fail',
    weight: 15,
    test: (p) => p.dkim === 'fail',
    label: 'DKIM signature failed',
  },
  {
    id: 'dmarc_fail',
    weight: 15,
    test: (p) => p.dmarc === 'fail',
    label: 'DMARC policy failed',
  },
  {
    id: 'reply_to_mismatch',
    weight: 20,
    test: (p) => p.fromReplyToMismatch,
    label: 'From and Reply-To domains do not match',
  },
  {
    id: 'urgency_language',
    weight: 15,
    test: (p) => countMatches(p.body, URGENCY_PATTERNS) >= 1,
    label: 'Urgency / pressure language detected in body',
  },
  {
    id: 'threat_language',
    weight: 10,
    test: (p) => countMatches(p.body, THREAT_PATTERNS) >= 1,
    label: 'Threatening consequence language (suspension, legal action, etc.)',
  },
  {
    id: 'sensitive_info_request',
    weight: 20,
    test: (p) => countMatches(p.body, SENSITIVE_INFO_PATTERNS) >= 1,
    label: 'Requests sensitive information (password, OTP, card/PIN, etc.)',
  },
  {
    id: 'suspicious_link',
    weight: 15,
    test: (p) => hasSuspiciousLink(p.body),
    label: 'Contains a suspicious or non-HTTPS link',
  },
  {
    id: 'brand_domain_mismatch',
    weight: 15,
    test: (p) => hasBrandDomainMismatch(p),
    label: 'Sender domain does not match the brand it claims to represent',
  },
  {
    id: 'generic_greeting',
    weight: 5,
    test: (p) => /dear (customer|user|member|sir\/madam|valued)/i.test(p.body),
    label: 'Generic, non-personalized greeting',
  },
];

const URGENCY_PATTERNS = [
  /urgent/i, /immediately/i, /act now/i, /within 24 hours/i,
  /right away/i, /as soon as possible/i, /limited time/i, /expire[sd]?\s*(today|soon)/i,
];

const THREAT_PATTERNS = [
  /suspend(ed)?/i, /clos(e|ure) of your account/i, /legal action/i,
  /penalty/i, /permanently (lock|disable|close)/i, /account (will be|has been) (suspended|locked|disabled)/i,
];

const SENSITIVE_INFO_PATTERNS = [
  /password/i, /\botp\b/i, /one[- ]time password/i, /pin\s*(number|code)?/i,
  /cvv/i, /card number/i, /social security/i, /aadhaar/i, /verify your identity/i,
];

function countMatches(text, patterns) {
  if (!text) return 0;
  return patterns.filter((p) => p.test(text)).length;
}

function urlFlagReasons(url) {
  const reasons = [];
  if (url.startsWith('http://')) reasons.push('Not HTTPS');
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) reasons.push('Raw IP address instead of domain');
  if (/(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly)/i.test(url)) reasons.push('URL shortener');
  if (/(verify|secure|login|update|confirm)-?/i.test(url) && !/\.(gov\.in|nic\.in)/i.test(url)) {
    reasons.push('Suspicious keyword in domain/path');
  }
  return reasons;
}

// Extracts every URL from the body along with why (if at all) it was flagged.
// Used by both the rubric (hasSuspiciousLink) and the URLs tab in the UI.
function extractUrls(body) {
  if (!body) return [];
  const urls = body.match(/https?:\/\/[^\s)]+/gi) || [];
  return urls.map((url) => {
    const reasons = urlFlagReasons(url);
    return { url, suspicious: reasons.length > 0, reasons };
  });
}

function hasSuspiciousLink(body) {
  return extractUrls(body).some((u) => u.suspicious);
}

// Checks if the email body mentions a well-known brand/institution
// but the sender's actual domain doesn't match that brand's real domain.
const KNOWN_BRANDS = {
  sbi: 'sbi.co.in',
  'state bank': 'sbi.co.in',
  google: 'google.com',
  microsoft: 'microsoft.com',
  amazon: 'amazon.in',
  paypal: 'paypal.com',
  github: 'github.com',
  icici: 'icicibank.com',
  hdfc: 'hdfcbank.com',
};

function hasBrandDomainMismatch(parsed) {
  const bodyLower = (parsed.body || '').toLowerCase();
  const fromDomainMatch = (parsed.from || '').match(/@([\w.-]+)/);
  const fromDomain = fromDomainMatch ? fromDomainMatch[1].toLowerCase() : null;
  if (!fromDomain) return false;

  for (const [brand, realDomain] of Object.entries(KNOWN_BRANDS)) {
    if (bodyLower.includes(brand) && !fromDomain.includes(realDomain.split('.')[0])) {
      return true;
    }
  }
  return false;
}

// Fusion weights: how much each signal contributes to the final score.
// Rubric (structural/header evidence) is weighted slightly higher since
// it's deterministic ground truth (SPF/DKIM/DMARC really did fail);
// the ML signal covers content/wording patterns the rubric doesn't.
const RUBRIC_FUSION_WEIGHT = 0.6;
const ML_FUSION_WEIGHT = 0.4;

async function classifyEmail(parsedEmail) {
  const triggered = RUBRIC.filter((rule) => {
    try {
      return rule.test(parsedEmail);
    } catch (e) {
      return false; // fail-safe: a broken rule never crashes the whole analysis
    }
  });

  const rubricScore = Math.min(100, triggered.reduce((sum, r) => sum + r.weight, 0));

  // ML text-classifier signal (see ml.js). Guarded so a missing/broken
  // model never crashes the analysis - falls back to rubric-only.
  let mlResult = { phishingProbability: null, topWords: [], tokensScored: 0 };
  try {
    const mlFn =
      (typeof mlClassifyText === 'function' && mlClassifyText) ||
      (typeof window !== 'undefined' && typeof window.mlClassifyText === 'function' && window.mlClassifyText) ||
      (typeof module !== 'undefined' && require('./ml.js').mlClassifyText);
    if (mlFn) {
      mlResult = mlFn(parsedEmail.body);
    }
  } catch (e) {
    mlResult = { phishingProbability: null, topWords: [], tokensScored: 0 };
  }

  const hasMlSignal = typeof mlResult.phishingProbability === 'number';
  const score = hasMlSignal
    ? Math.round(
        rubricScore * RUBRIC_FUSION_WEIGHT + mlResult.phishingProbability * ML_FUSION_WEIGHT
      )
    : rubricScore;

  let verdict;
  if (score >= 56) verdict = 'Malicious';
  else if (score >= 26) verdict = 'Suspicious';
  else verdict = 'Safe';

  const redFlags = triggered.map((r) => r.label);
  // Same triggered rules, but keeping the weight alongside each label so the
  // UI can show "how much" each indicator contributed (not just that it fired).
  const flaggedIndicators = triggered.map((r) => ({ id: r.id, label: r.label, weight: r.weight }));
  if (hasMlSignal && mlResult.phishingProbability >= 60 && mlResult.topWords.length > 0) {
    redFlags.push(`ML model flagged suspicious wording: ${mlResult.topWords.join(', ')}`);
    flaggedIndicators.push({
      id: 'ml_wording',
      label: `ML model flagged suspicious wording: ${mlResult.topWords.join(', ')}`,
      weight: Math.round(mlResult.phishingProbability * ML_FUSION_WEIGHT),
    });
  }

  const reasoning = buildReasoning(verdict, triggered, parsedEmail, hasMlSignal ? mlResult : null);
  const recommendedAction = buildRecommendation(verdict);

  return {
    verdict,
    confidence: score === 0 ? 92 : Math.max(score, 30), // baseline confidence even on clean emails
    reasoning,
    redFlags,
    flaggedIndicators,
    recommendedAction,
    _score: score, // exposed for debugging/demo transparency, not required by UI
    _rubricScore: rubricScore,
    _mlScore: hasMlSignal ? mlResult.phishingProbability : null,
  };
}

function buildReasoning(verdict, triggered, parsed, mlResult) {
  const mlNote = mlResult
    ? ` The ML text classifier independently rated the body content ${mlResult.phishingProbability}% likely phishing based on learned wording patterns.`
    : '';

  if (triggered.length === 0) {
    if (mlResult && mlResult.phishingProbability >= 50) {
      return `No rule-based indicators were triggered, but the ML text classifier flagged the wording as ${mlResult.phishingProbability}% likely phishing. Manual review recommended.`;
    }
    return `No phishing indicators were detected. Authentication checks passed and the message content shows no urgency, threat, or credential-harvesting patterns.${mlNote}`;
  }

  const topReasons = triggered.slice(0, 3).map((r) => r.label.toLowerCase());
  const verdictPhrase = verdict === 'Malicious'
    ? 'Multiple strong phishing indicators were found'
    : 'Some phishing indicators were found';

  return `${verdictPhrase}: ${topReasons.join('; ')}${triggered.length > 3 ? `, and ${triggered.length - 3} more` : ''}.${mlNote}`;
}

function buildRecommendation(verdict) {
  if (verdict === 'Malicious') return 'Do not click any links or reply. Delete the email and report it to your IT/security team.';
  if (verdict === 'Suspicious') return 'Do not click links. Verify the sender through an official channel before taking any action.';
  return 'No action needed, but always verify unexpected requests through a trusted channel.';
}

if (typeof module !== 'undefined') module.exports = { classifyEmail, RUBRIC, extractUrls };
