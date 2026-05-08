const dnsService = require('../recon/dnsService');
const subdomainEnum = require('../recon/subdomainEnum');
const techScanner = require('../scanner/techScanner');
const nmapScanner = require('../scanner/nmapScanner');
const webSecurityScanner = require('../scanner/webSecurityScanner');
const nucleiEngine = require('../vuln/nucleiEngine');
const intelService = require('../intel/intelService');
const scoringEngine = require('../engine/scoringEngine');
const recommendationEngine = require('../engine/recommendationEngine');
const validator = require('../utils/validator');

const SENSITIVE_PORTS = {
  21: ['FTP exposed to internet', 'Disable FTP or replace it with SFTP/SSH and enforce strong authentication.'],
  23: ['Telnet exposed to internet', 'Disable Telnet and use SSH with key-based authentication.'],
  445: ['SMB exposed to internet', 'Block SMB at the perimeter and expose file sharing only through VPN or private networks.'],
  1433: ['Microsoft SQL Server exposed', 'Restrict database access to trusted hosts and require encrypted authenticated connections.'],
  2375: ['Docker API exposed without TLS', 'Bind Docker API to localhost or enable TLS client authentication immediately.'],
  3306: ['MySQL exposed to internet', 'Restrict MySQL access to application hosts and rotate exposed credentials.'],
  3389: ['Remote Desktop exposed', 'Restrict RDP with VPN/MFA and monitor brute-force attempts.'],
  5432: ['PostgreSQL exposed to internet', 'Restrict PostgreSQL access to application hosts and require TLS.'],
  5900: ['VNC exposed to internet', 'Disable public VNC or require VPN and strong authentication.'],
  6379: ['Redis exposed to internet', 'Bind Redis privately, require authentication, and disable dangerous commands.'],
  9200: ['Elasticsearch exposed to internet', 'Enable authentication/TLS and restrict Elasticsearch to private networks.'],
  27017: ['MongoDB exposed to internet', 'Enable authentication, bind privately, and restrict network access.']
};

async function runAssessment(rawTarget) {
  const resolved = await validator.resolveTarget(rawTarget);
  const target = resolved.target;

  const [dns, whois, subdomains, nmap, technologies, webSecurity, nuclei, vt, abuse] = await Promise.all([
    withTimeout('DNS', dnsService.getDNSInfo(target), 8000, { error: 'DNS lookup timed out' }),
    withTimeout('WHOIS', dnsService.getWhoisInfo(target), 8000, { error: 'WHOIS lookup timed out' }),
    withTimeout('Subdomain enumeration', subdomainEnum.enumerateSubdomains(target), 10000, []),
    withTimeout('Nmap', nmapScanner.scanPorts(target), Number(process.env.NMAP_TOTAL_TIMEOUT_MS || 85000), {
      scanner: 'nmap',
      status: 'unavailable',
      ports: [],
      rawSummary: 'Nmap module timed out.'
    }),
    withTimeout('Technology detection', techScanner.analyzeTarget(target), 15000, { technologies: [] }),
    withTimeout('Web security checks', webSecurityScanner.scanWebSecurity(target), Number(process.env.WEB_CHECK_TOTAL_TIMEOUT_MS || 20000), {
      scanner: 'web-security',
      status: 'unavailable',
      findings: [],
      checks: [],
      error: 'Web security checks timed out'
    }),
    withTimeout('Nuclei', nucleiEngine.runScan([`https://${target}`, `http://${target}`]), Number(process.env.NUCLEI_TOTAL_TIMEOUT_MS || 125000), {
      status: 'unavailable',
      scanner: 'nuclei',
      findings: [],
      targets: [`https://${target}`, `http://${target}`],
      errors: ['Nuclei module timed out']
    }),
    withTimeout('VirusTotal', intelService.checkVirusTotal(target), 12000, { status: 'unavailable', summary: 'VirusTotal request timed out' }),
    withTimeout('AbuseIPDB', intelService.checkAbuseIPDB(resolved.ip), 12000, { status: 'unavailable', summary: 'AbuseIPDB request timed out' })
  ]);

  const webSecurityPorts = portsFromWebSecurity(webSecurity);
  const openPorts = mergeOpenPorts(nmap.ports, webSecurityPorts);
  const portScanResults = mergePortScanResults(nmap.results || nmap.ports || [], webSecurityPorts);
  const vulnerabilities = [
    ...(webSecurity.findings || []),
    ...normalizeNucleiFindings(nuclei.findings || []),
    ...findingsFromNmapScripts(target, openPorts),
    ...findingsFromOpenPorts(target, openPorts)
  ];

  const reportPayload = {
    target,
    ip: resolved.ip,
    addresses: resolved.addresses,
    scanUrl: resolved.scanUrl,
    scanType: 'Evidence-Based Vulnerability Assessment',
    workflow: ['Recon', 'Technology Detection', 'Port Scan', 'Vulnerability Scan', 'Threat Intel', 'Risk Analysis', 'Final Report'],
    recon: { dns, whois, subdomains },
    dns,
    whois,
    subdomains,
    nmap,
    openPorts,
    portScan: {
      scanner: nmap.scanner || 'node-tcp',
      status: nmap.status || 'unknown',
      addresses: nmap.addresses || resolved.addresses || [],
      results: portScanResults
    },
    technologies: technologies.technologies || [],
    webSecurity,
    vulnerabilityScan: nuclei,
    vulnerabilities,
    reputationIntel: { vt, abuse },
    scannerStatus: {
      nmap: nmap.status,
      nuclei: nuclei.status,
      webSecurity: webSecurity.status,
      technology: technologies.technologies?.length ? 'completed' : 'degraded',
      threatIntel: {
        virusTotal: vt.status,
        abuseIPDB: abuse.status
      }
    },
    scannerDiagnostics: buildScannerDiagnostics(nmap, nuclei, technologies, webSecurity, vt, abuse)
  };

  const { score, rating, breakdown, logs } = scoringEngine.calculateScore(reportPayload);
  const recommendations = recommendationEngine.generateRecommendations(reportPayload);

  return {
    ...reportPayload,
    score,
    rating,
    confidence: calculateConfidence(reportPayload.scannerStatus),
    breakdown,
    recommendations,
    analysisLogs: logs,
    createdAt: new Date()
  };
}

async function withTimeout(name, promise, timeoutMs, fallback) {
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => setTimeout(() => reject(new Error(`${name} timed out`)), timeoutMs))
    ]);
  } catch (error) {
    if (Array.isArray(fallback)) return fallback;
    return {
      ...fallback,
      error: error.message || `${name} failed`
    };
  }
}

function buildScannerDiagnostics(nmap, nuclei, technologies, webSecurity, vt, abuse) {
  return [
    {
      module: 'Port Scan',
      status: nmap.status || 'unknown',
      detail: nmap.rawSummary || (nmap.status === 'completed' ? 'Common TCP port scan completed.' : 'TCP port scan unavailable.')
    },
    {
      module: 'Nuclei',
      status: nuclei.status || 'unknown',
      detail: nuclei.errors?.length ? nuclei.errors.join('; ') : `Scanned ${nuclei.targets?.length || 0} URL variants with JSONL parsing.`
    },
    {
      module: 'Technology Detection',
      status: technologies.technologies?.length ? 'completed' : 'degraded',
      detail: technologies.technologies?.length ? `${technologies.technologies.length} fingerprints detected.` : 'WhatWeb unavailable or no fingerprints found.'
    },
    {
      module: 'Web Security Checks',
      status: webSecurity.status || 'unknown',
      detail: webSecurity.findings?.length
        ? `${webSecurity.findings.length} HTTP security issues detected.`
        : webSecurity.error || 'HTTP security headers and HTTPS behavior checked.'
    },
    {
      module: 'VirusTotal',
      status: vt.status || 'unavailable',
      detail: vt.summary || vt.error || vt.reason || 'API key not configured.'
    },
    {
      module: 'AbuseIPDB',
      status: abuse.status || 'unavailable',
      detail: abuse.summary || abuse.error || abuse.reason || 'API key not configured.'
    }
  ];
}

function calculateConfidence(status) {
  let confidence = 100;
  if (status.nmap !== 'completed') confidence -= 30;
  if (status.nuclei !== 'completed') confidence -= 40;
  if (status.technology !== 'completed') confidence -= 10;
  if (status.threatIntel?.virusTotal !== 'success') confidence -= 10;
  if (status.threatIntel?.abuseIPDB !== 'success') confidence -= 10;
  if (confidence >= 80) return 'High';
  if (confidence >= 50) return 'Medium';
  return 'Low';
}

function normalizeNucleiFindings(findings) {
  return findings.map((finding) => ({
    name: finding.name,
    severity: finding.severity,
    description: finding.description,
    matchedUrl: finding.matchedUrl,
    source: 'Nuclei',
    templateId: finding.templateId,
    cves: finding.cves || [],
    cvssScore: finding.cvssScore || null,
    cwe: finding.cwe || null,
    tags: finding.tags || [],
    remediation: finding.remediation || 'Apply the vendor or template-specific remediation and rescan to confirm closure.'
  }));
}

function mergeOpenPorts(...portLists) {
  const ports = [];
  const seen = new Set();

  portLists.flat().filter(Boolean).forEach((port) => {
    const status = String(port.status || port.state || 'open').toLowerCase();
    if (status !== 'open') return;
    const key = `${port.protocol || 'tcp'}:${port.port}`;
    if (seen.has(key)) return;
    seen.add(key);
    ports.push({ ...port, status: 'open', state: 'open' });
  });

  return ports.sort((a, b) => Number(a.port) - Number(b.port));
}

function mergePortScanResults(...portLists) {
  const portsByKey = new Map();
  const statusRank = { open: 3, closed: 2, filtered: 1 };

  portLists.flat().filter(Boolean).forEach((port) => {
    const normalized = normalizePortResult(port);
    const key = `${normalized.protocol}:${normalized.port}`;
    const existing = portsByKey.get(key);

    if (!existing || statusRank[normalized.status] > statusRank[existing.status]) {
      portsByKey.set(key, normalized);
    }
  });

  return Array.from(portsByKey.values()).sort((a, b) => Number(a.port) - Number(b.port));
}

function normalizePortResult(port) {
  const status = String(port.status || port.state || 'open').toLowerCase();
  const normalizedStatus = ['open', 'closed', 'filtered'].includes(status) ? status : 'filtered';

  return {
    port: Number(port.port),
    protocol: port.protocol || 'tcp',
    status: normalizedStatus,
    state: normalizedStatus,
    service: port.service || 'unknown',
    version: port.version || (normalizedStatus === 'open' ? 'unknown' : ''),
    responseTime: Number.isFinite(Number(port.responseTime)) ? Number(port.responseTime) : null,
    address: port.address || '',
    source: port.source || 'port-scan'
  };
}

function portsFromWebSecurity(webSecurity) {
  const ports = [];
  const checks = Array.isArray(webSecurity?.checks) ? webSecurity.checks : [];

  checks.forEach((check) => {
    if (!check.status) return;
    const isHttps = /^https:\/\//i.test(check.url || '');
    const isHttp = /^http:\/\//i.test(check.url || '');
    if (!isHttps && !isHttp) return;

    ports.push({
      port: isHttps ? 443 : 80,
      protocol: 'tcp',
      state: 'open',
      status: 'open',
      service: isHttps ? 'https' : 'http',
      product: '',
      version: `HTTP ${check.status}`,
      responseTime: check.responseTime ?? null,
      source: 'web-security-check'
    });
  });

  return ports;
}

function findingsFromOpenPorts(target, openPorts) {
  return openPorts
    .filter((port) => SENSITIVE_PORTS[port.port])
    .map((port) => {
      const [name, remediation] = SENSITIVE_PORTS[port.port];
      return {
        name,
        severity: [23, 445, 2375, 3389, 6379, 9200, 27017].includes(port.port) ? 'high' : 'medium',
        description: `Nmap confirmed ${port.service || 'unknown'} is reachable on TCP/${port.port}${port.version && port.version !== 'unknown' ? ` (${port.version})` : ''}. This increases external attack surface and may expose sensitive administrative or data services.`,
        matchedUrl: `${target}:${port.port}`,
        source: 'Nmap',
        remediation
      };
    });
}

function findingsFromNmapScripts(target, openPorts) {
  const findings = [];

  openPorts.forEach((port) => {
    (port.scripts || []).forEach((script) => {
      const output = script.output || '';
      const cves = [...new Set(output.match(/CVE-\d{4}-\d{4,7}/gi) || [])].map((cve) => cve.toUpperCase());
      const vulnerable = /VULNERABLE|State:\s*VULNERABLE|CVSS|CVE-\d{4}/i.test(output);
      if (!vulnerable) return;

      findings.push({
        name: cves.length ? `${port.service || 'service'} vulnerability: ${cves[0]}` : `Nmap NSE vulnerability finding on ${port.service || `TCP/${port.port}`}`,
        severity: /critical|CVSS:\s*(9|10)|CVSSv[23]:\s*(9|10)/i.test(output) ? 'critical' : /high|CVSS:\s*[7-8]/i.test(output) ? 'high' : 'medium',
        description: `Nmap script ${script.id} reported vulnerability evidence on TCP/${port.port}. ${output.slice(0, 700)}`,
        matchedUrl: `${target}:${port.port}`,
        source: `Nmap NSE (${script.id})`,
        cves,
        remediation: `Patch or reconfigure ${port.service || 'the affected service'} on TCP/${port.port}, then rerun Nmap/Nuclei validation.`
      });
    });
  });

  return findings;
}

module.exports = { runAssessment };
