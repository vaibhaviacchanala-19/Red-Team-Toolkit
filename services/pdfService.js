const PDFDocument = require('pdfkit');

function clean(value, fallback = 'N/A') {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch (error) {
      return fallback;
    }
  }
  return String(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

function generateReportPDF(report, stream) {
  const fullReport = report.fullReport || report;
  const doc = new PDFDocument({ margin: 50, size: 'A4' });
  doc.pipe(stream);

  doc.fillColor('#0f172a').fontSize(24).text('RED TEAM TOOLKIT', { align: 'center' });
  doc.fillColor('#475569').fontSize(14).text('Evidence-Based Security Assessment Report', { align: 'center' });
  doc.moveDown(1.5);

  doc.fillColor('#0f172a').fontSize(12);
  doc.text(`Target: ${clean(report.target || fullReport.target)}`);
  doc.text(`IP Address: ${clean(report.ip || fullReport.ip)}`);
  doc.text(`Scan Type: ${clean(fullReport.scanType || 'Evidence-Based Vulnerability Assessment')}`);
  doc.text(`Scan Date: ${new Date(report.createdAt || fullReport.createdAt || Date.now()).toLocaleString()}`);
  doc.moveDown();

  doc.rect(50, doc.y, 500, 60).fillOpacity(0.12).fill('#38bdf8').fillOpacity(1);
  doc.fillColor('#020617').fontSize(16).text(`Risk Score: ${clean(report.score ?? fullReport.score, 0)} / 100`, 60, doc.y + 12);
  doc.text(`Rating: ${clean(report.rating || fullReport.rating)}`, 60, doc.y + 32);
  doc.moveDown(3);

  doc.fillColor('#0f172a').fontSize(16).text('Open Ports & Services');
  doc.moveDown(0.5).fontSize(10);
  const ports = list(fullReport.openPorts);
  if (ports.length === 0) {
    doc.text('No open ports detected or port scan unavailable.');
  } else {
    ports.forEach((port) => {
      doc.text(`- ${clean(port.port)}/${clean(port.protocol || 'tcp')} - ${clean(port.service || 'unknown')} (${clean(port.version || 'version unavailable')})`);
    });
  }

  doc.addPage();
  doc.fillColor('#0f172a').fontSize(16).text('Vulnerability Findings');
  doc.moveDown(0.5).fontSize(11);
  const vulnerabilities = list(fullReport.vulnerabilities);
  if (vulnerabilities.length === 0) {
    doc.text('No confirmed vulnerabilities were identified during the scan.');
  } else {
    vulnerabilities.slice(0, 40).forEach((vuln, index) => {
      doc.fillColor('#0369a1').fontSize(12).text(`${index + 1}. ${clean(vuln.name, 'Vulnerability Finding')}`);
      doc.fillColor('#475569').fontSize(10).text(`Severity: ${clean(vuln.severity || 'unknown').toUpperCase()} | Source: ${clean(vuln.source || 'Unknown')}`);
      if (Array.isArray(vuln.cves) && vuln.cves.length > 0) doc.text(`CVEs: ${vuln.cves.map((cve) => clean(cve)).join(', ')}`);
      doc.fillColor('#0f172a').fontSize(10).text(`Description: ${clean(vuln.description || 'No description available.')}`);
      if (vuln.matchedUrl) doc.text(`Location: ${clean(vuln.matchedUrl)}`);
      if (vuln.remediation) doc.text(`Remediation: ${clean(vuln.remediation)}`);
      doc.moveDown(0.5);
    });
  }

  doc.addPage();
  doc.fillColor('#0f172a').fontSize(16).text('Threat Intelligence Summary');
  doc.moveDown(0.5).fontSize(11);
  const vt = fullReport.reputationIntel?.vt || {};
  const abuse = fullReport.reputationIntel?.abuse || {};
  doc.text(`VirusTotal: ${clean(vt.summary || vt.status || 'Unavailable')}`);
  doc.text(`Malicious detections: ${clean(vt.malicious ?? 0)}`);
  doc.text(`Suspicious detections: ${clean(vt.suspicious ?? 0)}`);
  doc.text(`ASN: ${clean(vt.asn || 'N/A')}`);
  doc.text(`Country: ${clean(vt.country || 'Unknown')}`);
  doc.moveDown(0.5);
  doc.text(`AbuseIPDB: ${clean(abuse.summary || abuse.status || 'Unavailable')}`);
  doc.text(`Abuse confidence: ${clean(abuse.abuseScore ?? 'N/A')}`);
  doc.text(`Total reports: ${clean(abuse.totalReports ?? 'N/A')}`);
  doc.text(`ISP: ${clean(abuse.isp || 'Unknown')}`);
  doc.text(`Usage type: ${clean(abuse.usageType || 'Unknown')}`);

  doc.addPage();
  doc.fillColor('#0f172a').fontSize(16).text('Recommendations');
  doc.moveDown(0.5).fontSize(11);
  const recs = list(fullReport.recommendations);
  if (recs.length === 0) {
    doc.text('No recommendations generated.');
  } else {
    recs.forEach((rec, index) => {
      doc.text(`${index + 1}. ${clean(rec)}`);
      doc.moveDown(0.35);
    });
  }

  doc.end();
}

module.exports = { generateReportPDF };
