const axios = require('axios');
const logger = require('../utils/logger');

const USER_AGENT = 'RedTeamToolkit/1.0';

async function scanWebSecurity(target) {
  const hostname = String(target || '').replace(/^https?:\/\//i, '').split('/')[0];
  const findings = [];
  const checks = [];

  const httpsResult = await requestUrl(`https://${hostname}`, 3);
  checks.push({
    url: `https://${hostname}`,
    status: httpsResult.status,
    responseTime: httpsResult.responseTime,
    error: httpsResult.error || ''
  });

  if (httpsResult.response) {
    findings.push(...findingsFromHttpsHeaders(hostname, httpsResult.response));
  }

  const httpResult = await requestUrl(`http://${hostname}`, 0);
  checks.push({
    url: `http://${hostname}`,
    status: httpResult.status,
    responseTime: httpResult.responseTime,
    error: httpResult.error || '',
    location: httpResult.headers.location || ''
  });

  if (httpResult.response) {
    findings.push(...findingsFromHttpBehavior(hostname, httpResult.response));
  }

  const deduped = dedupeFindings(findings);
  if (deduped.length) {
    logger.info(`Web security checks found ${deduped.length} issues for ${hostname}`);
  }

  return {
    scanner: 'web-security',
    status: httpsResult.response || httpResult.response ? 'completed' : 'unavailable',
    findings: deduped,
    checks,
    error: !httpsResult.response && !httpResult.response
      ? [httpsResult.error, httpResult.error].filter(Boolean).join('; ')
      : ''
  };
}

async function requestUrl(url, maxRedirects) {
  const startedAt = Date.now();
  try {
    const response = await axios.get(url, {
      timeout: Number(process.env.WEB_CHECK_TIMEOUT_MS || 12000),
      maxRedirects,
      validateStatus: () => true,
      headers: { 'User-Agent': USER_AGENT }
    });

    return {
      response,
      status: response.status,
      responseTime: Date.now() - startedAt,
      headers: normalizeHeaders(response.headers)
    };
  } catch (error) {
    return {
      response: null,
      status: null,
      responseTime: Date.now() - startedAt,
      headers: {},
      error: error.message
    };
  }
}

function findingsFromHttpsHeaders(hostname, response) {
  const h = normalizeHeaders(response.headers);
  const findings = [];
  const location = `https://${hostname}`;

  if (!h['strict-transport-security']) {
    findings.push({
      name: 'Missing HTTP Strict Transport Security header',
      severity: 'medium',
      description: 'The HTTPS response does not include Strict-Transport-Security, so browsers are not instructed to force future requests over HTTPS.',
      matchedUrl: location,
      source: 'Web Security Checks',
      remediation: 'Add a Strict-Transport-Security header with an appropriate max-age, includeSubDomains after validation, and preload only when ready.'
    });
  }

  if (!h['content-security-policy']) {
    findings.push({
      name: 'Missing Content Security Policy',
      severity: 'medium',
      description: 'The response does not include a Content-Security-Policy header, reducing browser-side protection against script injection and content loading abuse.',
      matchedUrl: location,
      source: 'Web Security Checks',
      remediation: 'Deploy a restrictive Content-Security-Policy, starting in report-only mode if needed, then enforce it after tuning.'
    });
  }

  if (!h['x-frame-options'] && !/frame-ancestors/i.test(h['content-security-policy'] || '')) {
    findings.push({
      name: 'Missing clickjacking protection',
      severity: 'medium',
      description: 'The response does not include X-Frame-Options or a CSP frame-ancestors directive, so pages may be frameable by untrusted origins.',
      matchedUrl: location,
      source: 'Web Security Checks',
      remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN, or define a CSP frame-ancestors policy.'
    });
  }

  if (!h['x-content-type-options']) {
    findings.push({
      name: 'Missing MIME sniffing protection',
      severity: 'low',
      description: 'The response does not include X-Content-Type-Options, allowing some browsers to MIME-sniff content.',
      matchedUrl: location,
      source: 'Web Security Checks',
      remediation: 'Add X-Content-Type-Options: nosniff to HTTP responses.'
    });
  }

  if (!h['referrer-policy']) {
    findings.push({
      name: 'Missing Referrer Policy',
      severity: 'low',
      description: 'The response does not include a Referrer-Policy header, which can leak URL paths or query data to third-party origins.',
      matchedUrl: location,
      source: 'Web Security Checks',
      remediation: 'Set a Referrer-Policy such as strict-origin-when-cross-origin or no-referrer depending on application needs.'
    });
  }

  if (h.server && !/cloudflare|akamai|awselb|elb/i.test(h.server)) {
    findings.push({
      name: 'Server technology disclosure',
      severity: 'info',
      description: `The Server header discloses backend technology: ${h.server}.`,
      matchedUrl: location,
      source: 'Web Security Checks',
      remediation: 'Reduce verbose server headers where supported, and keep disclosed software fully patched.'
    });
  }

  findings.push(...findingsFromCookies(location, response.headers['set-cookie']));
  return findings;
}

function findingsFromHttpBehavior(hostname, response) {
  const h = normalizeHeaders(response.headers);
  const status = Number(response.status);
  const location = h.location || '';
  const redirectsToHttps = status >= 300 && status < 400 && /^https:\/\//i.test(location);

  if (!redirectsToHttps && status < 500) {
    return [{
      name: 'HTTP endpoint does not enforce HTTPS redirect',
      severity: 'medium',
      description: 'The plain HTTP endpoint did not redirect directly to HTTPS, allowing users to access the site without transport encryption.',
      matchedUrl: `http://${hostname}`,
      source: 'Web Security Checks',
      remediation: 'Redirect all HTTP requests to the equivalent HTTPS URL before serving application content.'
    }];
  }

  return [];
}

function findingsFromCookies(location, rawCookies) {
  const cookies = Array.isArray(rawCookies) ? rawCookies : rawCookies ? [rawCookies] : [];
  const findings = [];

  cookies.forEach((cookie) => {
    const name = String(cookie).split('=')[0] || 'cookie';
    const lower = String(cookie).toLowerCase();
    if (!lower.includes('; secure')) {
      findings.push(cookieFinding(name, 'Cookie missing Secure attribute', 'low', 'The cookie can be sent over unencrypted HTTP if the browser reaches an HTTP endpoint.', location, 'Set the Secure attribute on cookies that are only needed over HTTPS.'));
    }
    if (!lower.includes('; httponly')) {
      findings.push(cookieFinding(name, 'Cookie missing HttpOnly attribute', 'low', 'Client-side scripts may be able to read the cookie if an XSS issue exists.', location, 'Set the HttpOnly attribute on session and sensitive cookies.'));
    }
    if (!lower.includes('; samesite=')) {
      findings.push(cookieFinding(name, 'Cookie missing SameSite attribute', 'low', 'The cookie does not declare cross-site request behavior.', location, 'Set SameSite=Lax or SameSite=Strict unless cross-site usage is required.'));
    }
  });

  return findings;
}

function cookieFinding(cookieName, name, severity, description, matchedUrl, remediation) {
  return {
    name: `${name}: ${cookieName}`,
    severity,
    description,
    matchedUrl,
    source: 'Web Security Checks',
    remediation
  };
}

function normalizeHeaders(headers) {
  return Object.keys(headers || {}).reduce((acc, key) => {
    const value = headers[key];
    acc[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value || '');
    return acc;
  }, {});
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = [finding.name, finding.matchedUrl].join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { scanWebSecurity };
