function calculateScore(findings) {
  let score = 100;
  const logs = [];
  const breakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  const vulnerabilities = Array.isArray(findings.vulnerabilities) ? findings.vulnerabilities : [];
  vulnerabilities.forEach((vulnerability) => {
    const severity = (vulnerability.severity || 'low').toLowerCase();
    let deduction = 0;

    switch (severity) {
      case 'critical': deduction = 35; breakdown.critical += 1; break;
      case 'high': deduction = 20; breakdown.high += 1; break;
      case 'medium': deduction = 10; breakdown.medium += 1; break;
      case 'low': deduction = 4; breakdown.low += 1; break;
      default: deduction = 1; breakdown.info += 1; break;
    }

    if (Array.isArray(vulnerability.cves) && vulnerability.cves.length > 0) {
      deduction += severity === 'critical' ? 10 : 5;
    }

    score -= deduction;
    logs.push(`Found ${severity.toUpperCase()} issue: ${vulnerability.name} (-${deduction})`);
  });

  const openPorts = Array.isArray(findings.openPorts) ? findings.openPorts : [];
  if (openPorts.length > 5) {
    score -= 10;
    logs.push('Wide attack surface detected: more than 5 open ports (-10)');
  }

  const criticalServices = [21, 23, 445, 1433, 1521, 2049, 2375, 3306, 5432, 5900, 6379, 9200, 27017];
  openPorts.forEach((port) => {
    if (criticalServices.includes(port.port)) {
      score -= 8;
      logs.push(`Sensitive exposed service ${port.port} (${port.service}) detected (-8)`);
    }
  });

  const intel = findings.reputationIntel || {};
  const vt = intel.vt || {};
  const abuse = intel.abuse || {};

  if (vt.malicious > 0) {
    const vtPenalty = Math.min(vt.malicious * 10 + (vt.suspicious || 0) * 5, 35);
    score -= vtPenalty;
    logs.push(`VirusTotal flagged malicious indicators (-${vtPenalty})`);
  }

  if (abuse.abuseScore > 75) {
    score -= 20;
    logs.push('AbuseIPDB confidence above 75 (-20)');
  } else if (abuse.abuseScore > 40) {
    score -= 10;
    logs.push('AbuseIPDB confidence above 40 (-10)');
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;
  score = Math.round(score);

  const rating = score < 40 ? 'High Risk' : score < 70 ? 'Medium Risk' : 'Low Risk';
  return { score, rating, breakdown, logs };
}

module.exports = { calculateScore };
