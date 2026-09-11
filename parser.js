// ============================================================
// EMAIL HEADER PARSER
// Extracts: sender IP, SPF/DKIM/DMARC status, Received chain,
// From/Reply-To mismatch, Subject, Body
// ============================================================

function parseEmail(rawEmail) {
  const lines = rawEmail.split('\n');
  const headers = {};
  let currentHeader = null;
  let bodyStartIndex = -1;

  // Split headers from body (blank line separates them)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.trim() === '' && bodyStartIndex === -1) {
      bodyStartIndex = i + 1;
      break;
    }

    // Header continuation (starts with whitespace)
    if (/^\s/.test(line) && currentHeader) {
      headers[currentHeader] += ' ' + line.trim();
      continue;
    }

    const match = line.match(/^([A-Za-z-]+):\s*(.*)$/);
    if (match) {
      currentHeader = match[1].toLowerCase();
      if (headers[currentHeader]) {
        // Multiple headers with same name (e.g. multiple Received:)
        headers[currentHeader] = Array.isArray(headers[currentHeader])
          ? [...headers[currentHeader], match[2]]
          : [headers[currentHeader], match[2]];
      } else {
        headers[currentHeader] = match[2];
      }
    }
  }

  const body = bodyStartIndex > -1 ? lines.slice(bodyStartIndex).join('\n').trim() : '';

  return {
    headers,
    body,
    from: headers['from'] || null,
    replyTo: headers['reply-to'] || null,
    subject: headers['subject'] || '(no subject)',
    to: headers['to'] || null,
    date: headers['date'] || null,
    senderIP: extractSenderIP(headers),
    spf: extractAuthResult(headers, 'spf'),
    dkim: extractAuthResult(headers, 'dkim'),
    dmarc: extractAuthResult(headers, 'dmarc'),
    fromReplyToMismatch: checkFromReplyToMismatch(headers['from'], headers['reply-to']),
    receivedChain: extractReceivedChain(headers),
  };
}

// Extract the originating sender IP from Received headers.
// Strategy: look at the EARLIEST (bottom-most / last) Received header,
// since that's closest to the original sender.
function extractSenderIP(headers) {
  const received = headers['received'];
  if (!received) return null;

  const receivedArr = Array.isArray(received) ? received : [received];
  const lastReceived = receivedArr[receivedArr.length - 1];

  // Match IPv4 in brackets, e.g. "from mail.example.com ([203.0.113.45])"
  const ipMatch = lastReceived.match(/\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/);
  return ipMatch ? ipMatch[1] : null;
}

function extractReceivedChain(headers) {
  const received = headers['received'];
  if (!received) return [];
  const receivedArr = Array.isArray(received) ? received : [received];
  return receivedArr.map(r => r.substring(0, 120)); // trim for display
}

// SPF/DKIM/DMARC results usually live in Authentication-Results header
// e.g. "spf=pass smtp.mailfrom=example.com; dkim=fail; dmarc=fail"
function extractAuthResult(headers, type) {
  const authResults = headers['authentication-results'];
  if (!authResults) return 'unknown';

  const flat = Array.isArray(authResults) ? authResults.join(' ') : authResults;
  const regex = new RegExp(type + '=(\\w+)', 'i');
  const match = flat.match(regex);
  return match ? match[1].toLowerCase() : 'unknown';
}

function checkFromReplyToMismatch(from, replyTo) {
  if (!from || !replyTo) return false;

  const extractDomain = (str) => {
    const emailMatch = str.match(/@([\w.-]+)/);
    return emailMatch ? emailMatch[1].toLowerCase() : null;
  };

  const fromDomain = extractDomain(from);
  const replyToDomain = extractDomain(replyTo);

  return fromDomain && replyToDomain && fromDomain !== replyToDomain;
}

// Export for use in main app
if (typeof module !== 'undefined') module.exports = { parseEmail };
