function generateRecommendations(findings) {
  const recommendations = new Set();
  const vulns = Array.isArray(findings.vulnerabilities) ? findings.vulnerabilities : [];
  const openPorts = Array.isArray(findings.openPorts) ? findings.openPorts : [];
  const techs = Array.isArray(findings.technologies) ? findings.technologies : [];
  const vt = findings.reputationIntel?.vt || {};
  const abuse = findings.reputationIntel?.abuse || {};

  vulns.forEach((vuln) => {
    const severity = (vuln.severity || 'low').toLowerCase();
    if (severity === 'critical') {
      recommendations.add(`Immediate remediation required: patch ${vuln.name} and verify the fix in a staging environment.`);
    }
    if (severity === 'high') {
      recommendations.add(`Address ${vuln.name} quickly. Review related configuration and patch the affected package.`);
    }
    if (vuln.name.match(/admin|login|wp-admin|phpmyadmin/i)) {
      recommendations.add('Restrict access to administrative and login pages using VPN, IP allowlisting, or WAF rules.');
    }
    if (vuln.remediation) {
      recommendations.add(`${vuln.name}: ${vuln.remediation}`);
    }
    if (Array.isArray(vuln.cves) && vuln.cves.length > 0) {
      recommendations.add(`Track and patch affected components for ${vuln.cves.join(', ')}; prioritize internet-facing systems.`);
    }
  });

  openPorts.forEach((port) => {
    if ([21, 23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 27017].includes(port.port)) {
      recommendations.add(`Restrict or disable service on port ${port.port} (${port.service}). Legacy services are high-risk exposure.`);
    }
    if (port.version && /outdated|vulnerable|cgi|unknown/i.test(port.version)) {
      recommendations.add(`Update service on port ${port.port} (${port.service}) to a maintained version.`);
    }
  });

  if (vt.malicious > 0 || vt.suspicious > 0) {
    recommendations.add('Investigate the target for signs of abuse or compromise based on threat intelligence findings.');
  }

  if (abuse.abuseScore > 50) {
    recommendations.add('Review IP reputation and consider network reputation-based filtering for this asset.');
  }

  if (techs.some((tech) => /wordpress|wp-|php/i.test(tech))) {
    recommendations.add('Audit WordPress plugins and themes; update to the latest secure versions.');
  }

  if (techs.some((tech) => /nginx|apache|iis/i.test(tech))) {
    recommendations.add('Review server configuration and disable unused modules to reduce attack surface.');
  }

  if (recommendations.size === 0) {
    recommendations.add('Maintain regular scanning cadence and validate patches for any discovered exposure.');
  }

  return Array.from(recommendations).slice(0, 7);
}

module.exports = { generateRecommendations };
