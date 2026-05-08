const state = { currentReport: null, progressTimer: null };

const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));

document.addEventListener('DOMContentLoaded', () => {
  $('scanForm').addEventListener('submit', startScan);
  $('exportBtn').addEventListener('click', exportJson);
  $('pdfBtn').addEventListener('click', exportPdf);
  $('fullReportPdfBtn').addEventListener('click', exportPdf);

  document.querySelectorAll('.tab-btn').forEach((button) => {
    button.addEventListener('click', () => switchTab(button.dataset.tab));
  });
});

async function startScan(event) {
  event.preventDefault();
  const target = $('targetInput').value.trim();
  if (!target) return;

  setLoading(true);
  $('errorMessage').classList.add('hidden');
  $('resultsArea').classList.add('hidden');

  try {
    const response = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Scan failed.');

    state.currentReport = data;
    renderReport(data);
    $('resultsArea').classList.remove('hidden');
    $('resultsArea').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    $('errorMessage').textContent = error.message === 'Failed to fetch'
      ? 'Backend server is not reachable. Start it with npm start, then refresh this page.'
      : error.message;
    $('errorMessage').classList.remove('hidden');
  } finally {
    setLoading(false);
  }
}

function setLoading(isLoading) {
  const button = $('scanBtn');
  button.disabled = isLoading;
  button.querySelector('.btn-text').textContent = isLoading ? 'Scanning' : 'Start Scan';
  button.querySelector('.loader').classList.toggle('hidden', !isLoading);
  $('scanProgress').classList.toggle('hidden', !isLoading);

  clearInterval(state.progressTimer);
  if (isLoading) {
    const steps = ['Resolving target', 'Running recon', 'Detecting technologies', 'Scanning ports', 'Executing Nuclei', 'Checking threat intel', 'Scoring risk'];
    let index = 0;
    $('progressText').textContent = steps[index];
    state.progressTimer = setInterval(() => {
      index = Math.min(index + 1, steps.length - 1);
      $('progressText').textContent = steps[index];
    }, 3500);
  }
}

function renderReport(report) {
  const breakdown = report.breakdown || {};
  const total = (report.vulnerabilities || []).length;
  const portResults = getPortResults(report);
  const openPortCount = portResults.filter((port) => getPortStatus(port) === 'open').length;
  $('resTarget').textContent = report.target;
  $('resIP').textContent = `${report.ip} | ${openPortCount} open ports`;
  $('resScore').textContent = report.score;
  $('resRating').textContent = report.rating;
  $('totalVulns').textContent = total;
  $('severityLine').textContent = `${breakdown.critical || 0} critical, ${breakdown.high || 0} high, ${breakdown.medium || 0} medium, ${breakdown.low || 0} low`;

  const color = scoreColor(report.score);
  $('scoreGauge').style.background = `conic-gradient(${color} ${report.score * 3.6}deg, rgba(255,255,255,0.08) 0deg)`;
  $('resRating').style.color = color;

  renderIntelSummary(report.reputationIntel || {});
  renderFindings('topFindings', (report.vulnerabilities || []).slice(0, 5));
  renderFindings('vulnList', report.vulnerabilities || []);
  renderRecommendations(report.recommendations || []);
  renderPorts(portResults);
  renderTechnologies(report.technologies || []);
  renderThreatIntel(report.reputationIntel || {});
  renderDiagnostics(report.scannerDiagnostics || [], report.confidence);
  renderReportPreview(report);
}

function renderFindings(elementId, findings) {
  const element = $(elementId);
  if (!findings.length) {
    element.innerHTML = '<div class="empty">No confirmed vulnerability findings were returned by the completed checks.</div>';
    return;
  }

  element.innerHTML = findings.map((finding) => `
    <article class="finding ${escapeHtml(finding.severity || 'info')}">
      <div class="finding-head">
        <strong>${escapeHtml(finding.name)}</strong>
        <span>${escapeHtml(finding.severity || 'info')}</span>
      </div>
      <p>${escapeHtml(finding.description || 'No description available.')}</p>
      <div class="finding-meta">
        <small>Source: ${escapeHtml(finding.source || 'Unknown')}</small>
        ${finding.templateId ? `<small>Template: ${escapeHtml(finding.templateId)}</small>` : ''}
        ${finding.cves?.length ? `<small>CVEs: ${escapeHtml(finding.cves.join(', '))}</small>` : ''}
        ${finding.matchedUrl ? `<small>Location: ${escapeHtml(finding.matchedUrl)}</small>` : ''}
      </div>
      ${finding.remediation ? `<div class="remediation">${escapeHtml(finding.remediation)}</div>` : ''}
    </article>
  `).join('');
}

function renderRecommendations(recommendations) {
  $('recList').innerHTML = recommendations.length
    ? recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join('')
    : '<li>No dynamic recommendations generated.</li>';
}

function renderPorts(ports) {
  $('portsBody').innerHTML = ports.length
    ? ports.map((port) => `
      <tr>
        <td>${escapeHtml(port.port)}/${escapeHtml(port.protocol || 'tcp')}</td>
        <td>${escapeHtml(port.service || 'unknown')}</td>
        <td>${escapeHtml(formatPortDetail(port))}</td>
        <td><span class="state-${escapeHtml(getPortStatus(port))}">${escapeHtml(getPortStatus(port))}</span></td>
      </tr>
    `).join('')
    : '<tr><td colspan="4">No port scan results returned. The scanner may have timed out or DNS resolution may have failed.</td></tr>';
}

function getPortResults(report) {
  const results = report.portScan?.results;
  if (Array.isArray(results) && results.length) return results;
  return report.openPorts || [];
}

function getPortStatus(port) {
  const status = String(port.status || port.state || 'open').toLowerCase();
  return ['open', 'closed', 'filtered'].includes(status) ? status : 'filtered';
}

function formatPortDetail(port) {
  const status = getPortStatus(port);
  if (status === 'open') {
    const version = port.version && port.version !== 'unknown' ? port.version : 'reachable';
    return port.responseTime != null ? `${version} (${port.responseTime}ms)` : version;
  }
  if (status === 'closed') return 'connection refused';
  return port.responseTime != null ? `timed out (${port.responseTime}ms)` : 'timed out or filtered';
}

function renderTechnologies(technologies) {
  $('techList').innerHTML = technologies.length
    ? technologies.map((tech) => `<span class="tech-pill">${escapeHtml(tech)}</span>`).join('')
    : '<div class="empty">No technologies identified by WhatWeb or HTTP fingerprint fallback.</div>';
}

function renderIntelSummary(intel) {
  const vt = intel.vt || {};
  const abuse = intel.abuse || {};
  const flagged = (vt.malicious || 0) > 0 || (vt.suspicious || 0) > 0 || (abuse.abuseScore || 0) > 25;
  $('intelStatus').textContent = flagged ? 'Flagged' : (vt.status === 'success' || abuse.status === 'success' ? 'Clean' : 'Unavailable');
  $('intelSummary').textContent = `${vt.summary || 'VirusTotal unavailable'} | ${abuse.summary || 'AbuseIPDB unavailable'}`;
}

function renderThreatIntel(intel) {
  const vt = intel.vt || {};
  const abuse = intel.abuse || {};
  $('intelGrid').innerHTML = `
    <article class="intel-card">
      <h3>VirusTotal</h3>
      <dl>
        <dt>Status</dt><dd>${escapeHtml(vt.status || 'unavailable')}</dd>
        <dt>Malicious</dt><dd>${escapeHtml(vt.malicious ?? 0)}</dd>
        <dt>Suspicious</dt><dd>${escapeHtml(vt.suspicious ?? 0)}</dd>
        <dt>ASN</dt><dd>${escapeHtml(vt.asn || 'N/A')}</dd>
        <dt>Country</dt><dd>${escapeHtml(vt.country || 'Unknown')}</dd>
      </dl>
    </article>
    <article class="intel-card">
      <h3>AbuseIPDB</h3>
      <dl>
        <dt>Status</dt><dd>${escapeHtml(abuse.status || 'unavailable')}</dd>
        <dt>Confidence</dt><dd>${escapeHtml(abuse.abuseScore ?? 0)}%</dd>
        <dt>Reports</dt><dd>${escapeHtml(abuse.totalReports ?? 0)}</dd>
        <dt>ISP</dt><dd>${escapeHtml(abuse.isp || 'Unknown')}</dd>
        <dt>Usage</dt><dd>${escapeHtml(abuse.usageType || 'Unknown')}</dd>
      </dl>
    </article>
  `;
}

function renderDiagnostics(items, confidence) {
  const visibleItems = items.filter((item) => {
    const module = String(item.module || '').toLowerCase();
    const status = String(item.status || '').toLowerCase();
    if ((module === 'nmap' || module === 'nuclei') && status !== 'completed') {
      return false;
    }
    return true;
  });

  $('scannerDiagnostics').innerHTML = `
    <article class="diagnostic-card confidence">
      <strong>Assessment Confidence</strong>
      <span>${escapeHtml(confidence || 'Unknown')}</span>
    </article>
    ${visibleItems.map((item) => `
      <article class="diagnostic-card ${escapeHtml(item.status || 'unknown')}">
        <strong>${escapeHtml(item.module)}</strong>
        <span>${escapeHtml(item.status || 'unknown')}</span>
        <p>${escapeHtml(item.detail || '')}</p>
      </article>
    `).join('')}
  `;
}

function renderReportPreview(report) {
  const vulnCount = report.vulnerabilities?.length || 0;
  const portCount = getPortResults(report).filter((port) => getPortStatus(port) === 'open').length;
  const topFindings = (report.vulnerabilities || []).slice(0, 6);

  $('pdfReportSummary').textContent = `Professional PDF report for ${report.target}, including ${vulnCount} findings, ${portCount} open services, threat intelligence, scoring, and recommendations.`;
  $('reportPreview').innerHTML = `
    <article class="report-section">
      <h3>Executive Summary</h3>
      <p>${escapeHtml(report.target)} was assessed with recon, technology detection, Nmap service analysis, Nuclei vulnerability scanning, threat intelligence, and risk scoring. Final rating: ${escapeHtml(report.rating)} with score ${escapeHtml(report.score)}/100.</p>
    </article>
    <article class="report-section">
      <h3>Assessment Coverage</h3>
      <div class="report-kpis">
        <span>${escapeHtml(vulnCount)} vulnerabilities</span>
        <span>${escapeHtml(portCount)} open services</span>
        <span>${escapeHtml(report.confidence || 'Unknown')} confidence</span>
      </div>
    </article>
    <article class="report-section">
      <h3>Top Findings</h3>
      ${topFindings.length ? topFindings.map((finding) => `
        <div class="report-finding">
          <strong>${escapeHtml(finding.name)}</strong>
          <span>${escapeHtml(finding.severity || 'unknown')}</span>
        </div>
      `).join('') : '<p>No confirmed vulnerability findings were identified.</p>'}
    </article>
  `;
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach((button) => button.classList.toggle('active', button.dataset.tab === tabId));
  document.querySelectorAll('.tab-content').forEach((content) => content.classList.toggle('active', content.id === tabId));
}

async function openHistory() {
  $('historyList').innerHTML = '<div class="empty">Loading history...</div>';
  try {
    const response = await fetch('/history');
    const history = await response.json();
    if (!response.ok) throw new Error(history.error || 'Failed to load history');
    $('historyList').innerHTML = history.length
      ? history.map((item) => `
        <article class="history-item">
          <button onclick="viewReport('${escapeHtml(item._id)}')">
            <strong>${escapeHtml(item.target)}</strong>
            <span>${escapeHtml(item.rating)} | ${escapeHtml(item.score)}/100</span>
            <small>${new Date(item.createdAt).toLocaleString()}</small>
          </button>
          <button class="delete-btn" onclick="deleteReport('${escapeHtml(item._id)}')">Delete</button>
        </article>
      `).join('')
      : '<div class="empty">No scans saved yet.</div>';
  } catch (error) {
    $('historyList').innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

async function viewReport(id) {
  const response = await fetch(`/report/${id}`);
  const data = await response.json();
  if (!response.ok) return;
  state.currentReport = { _id: data._id, ...(data.fullReport || data) };
  renderReport(state.currentReport);
  $('resultsArea').classList.remove('hidden');
  switchTab('overview');
}

async function deleteReport(id) {
  await fetch(`/report/${id}`, { method: 'DELETE' });
  openHistory();
}

function exportJson() {
  if (!state.currentReport) return;
  const blob = new Blob([JSON.stringify(state.currentReport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `red_team_report_${state.currentReport.target}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

async function exportPdf() {
  if (!state.currentReport) return;

  try {
    const response = await fetch('/report/pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: state.currentReport })
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Failed to generate PDF' }));
      throw new Error(error.error || 'Failed to generate PDF');
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `red_team_report_${state.currentReport.target || 'scan'}.pdf`;
    link.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    alert(error.message);
  }
}

function scoreColor(score) {
  if (score < 40) return '#ef4444';
  if (score < 70) return '#f59e0b';
  return '#22c55e';
}

window.viewReport = viewReport;
window.deleteReport = deleteReport;
