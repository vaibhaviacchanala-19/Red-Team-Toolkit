const logger = require('../utils/logger');
const { runCommand } = require('../utils/commandRunner');
const { resolveToolBin } = require('../utils/toolResolver');

async function runScan(targets) {
  const targetList = Array.isArray(targets) ? targets : [targets];
  const uniqueTargets = [...new Set(targetList.filter(Boolean))];
  logger.info(`Running Nuclei vulnerability scan for ${uniqueTargets.join(', ')}`);

  const runs = [];
  for (const target of uniqueTargets) {
    runs.push(await runSingleNucleiScan(target));
  }

  const findings = dedupeFindings(runs.flatMap((run) => run.findings || []));
  const failedRuns = runs.filter((run) => run.status === 'unavailable');
  const partialRuns = runs.filter((run) => run.status === 'partial');
  return {
    status: findings.length > 0 ? 'completed' : failedRuns.length === runs.length ? 'unavailable' : partialRuns.length ? 'partial' : 'completed',
    scanner: 'nuclei',
    findings,
    targets: uniqueTargets,
    errors: runs.map((run) => run.error).filter(Boolean)
  };
}

async function runSingleNucleiScan(target) {
  const severities = process.env.NUCLEI_SEVERITIES || 'low,medium,high,critical';
  const args = [
    '-u',
    target,
    '-jsonl',
    '-silent',
    '-severity',
    severities,
    '-rate-limit',
    process.env.NUCLEI_RATE_LIMIT || '30',
    '-timeout',
    process.env.NUCLEI_TEMPLATE_TIMEOUT || '8',
    '-retries',
    '1'
  ];

  if (process.env.NUCLEI_TEMPLATES) {
    args.push('-t', process.env.NUCLEI_TEMPLATES);
  }

  const nucleiBin = resolveToolBin('NUCLEI_BIN', 'nuclei', ['tools/nuclei/nuclei.exe']);
  const result = await runCommand(nucleiBin, args, {
    timeoutMs: Number(process.env.NUCLEI_TIMEOUT_MS || 120000)
  });

  const findings = parseNucleiOutput(result.stdout);

  if (!result.ok && !result.stdout) {
    const reason = result.error?.message || result.stderr || (result.timedOut ? 'timeout' : `exit code ${result.code}`);
    logger.warn(`Nuclei unavailable or failed: ${reason}`);
    return {
      status: 'unavailable',
      scanner: 'nuclei',
      findings: [],
      target,
      error: String(reason).slice(0, 500)
    };
  }

  return {
    status: result.timedOut ? 'partial' : 'completed',
    scanner: 'nuclei',
    target,
    findings,
    error: result.timedOut ? 'Nuclei timed out before completing all templates.' : '',
    stderr: result.stderr ? result.stderr.slice(0, 1000) : ''
  };
}

function parseNucleiOutput(data) {
  const findings = [];
  const lines = data.split('\n');

  lines.forEach((line) => {
    if (!line.trim()) return;
    try {
      const json = JSON.parse(line);
      if (!json.info) return;
      const classification = json.info.classification || {};
      const cves = []
        .concat(classification['cve-id'] || [])
        .filter(Boolean);

      findings.push({
        name: json.info?.name || 'Nuclei Finding',
        severity: normalizeSeverity(json.info?.severity),
        templateId: json['template-id'] || 'unknown',
        matchedUrl: json['matched-at'] || json.host || '',
        description: json.info?.description || 'Detected issue based on Nuclei template.',
        source: 'Nuclei',
        cves,
        cvssScore: classification['cvss-score'] || null,
        cwe: classification['cwe-id'] || null,
        tags: json.info?.tags || [],
        remediation: json.info?.remediation || remediationFor(json.info?.name, json.info?.severity)
      });
    } catch (err) {
      // Skip incomplete lines or non-JSON output
    }
  });

  return findings;
}

function normalizeSeverity(severity) {
  const normalized = String(severity || 'medium').toLowerCase();
  return ['critical', 'high', 'medium', 'low', 'info'].includes(normalized) ? normalized : 'medium';
}

function remediationFor(name, severity) {
  const text = String(name || '').toLowerCase();
  if (/cve|rce|injection|takeover/.test(text) || severity === 'critical') {
    return 'Patch the affected software immediately, verify the fix, and review exposure logs for compromise indicators.';
  }
  if (/admin|panel|login/.test(text)) {
    return 'Restrict administrative access with VPN or IP allowlisting and enforce strong authentication.';
  }
  if (/default credential|default password/.test(text)) {
    return 'Disable default accounts and rotate all credentials associated with the exposed service.';
  }
  if (/exposed|backup|env|config|directory listing/.test(text)) {
    return 'Remove the exposed resource from the public web root and add explicit access controls.';
  }
  if (/tls|ssl|cipher/.test(text)) {
    return 'Disable weak protocols/ciphers and deploy a current TLS configuration.';
  }
  return 'Review the affected asset, validate the finding, and apply the vendor or template-specific remediation.';
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = [finding.templateId, finding.matchedUrl, finding.name].join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { runScan };
