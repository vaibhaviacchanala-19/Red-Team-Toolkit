const axios = require('axios');
const techDetector = require('../recon/techDetector');
const logger = require('../utils/logger');
const { runCommand } = require('../utils/commandRunner');
const { resolveToolBin } = require('../utils/toolResolver');

async function analyzeTarget(target) {
  const normalized = target.startsWith('http') ? target : `https://${target}`;
  const result = await runWhatWeb(target);

  if (result.length > 0) {
    return { technologies: result };
  }

  try {
    const response = await axios.get(normalized, {
      timeout: 8000,
      maxRedirects: 2,
      validateStatus: (status) => status < 500,
      headers: { 'User-Agent': 'RedTeamToolkit/1.0' }
    });

    return { technologies: techDetector.detectTech(response.headers) };
  } catch (error) {
    logger.warn(`Tech detection fallback failed for ${target}: ${error.message}`);
    return { technologies: techDetector.detectTech({}) };
  }
}

async function runWhatWeb(target) {
  const findings = new Set();
  const whatwebBin = resolveToolBin('WHATWEB_BIN', 'whatweb');
  const result = await runCommand(whatwebBin, ['--log-json=-', '--no-errors', '--quiet', target], {
    timeoutMs: Number(process.env.WHATWEB_TIMEOUT_MS || 25000)
  });

  if (!result.ok || !result.stdout.trim()) {
    const reason = result.error?.message || result.stderr || (result.timedOut ? 'timeout' : `exit code ${result.code}`);
    logger.warn(`WhatWeb unavailable or failed: ${reason}`);
    return [];
  }

  try {
    const parsed = JSON.parse(result.stdout);
    const records = Array.isArray(parsed) ? parsed : [parsed];
    records.forEach((record) => {
      const plugins = record.plugins || {};
      Object.keys(plugins).forEach((name) => {
        const plugin = plugins[name] || {};
        const version = Array.isArray(plugin.version) && plugin.version.length > 0 ? ` ${plugin.version[0]}` : '';
        findings.add(`${name}${version}`);
      });
    });
  } catch (error) {
    logger.warn(`WhatWeb parse error: ${error.message}`);
  }

  return Array.from(findings);
}

module.exports = { analyzeTarget };
