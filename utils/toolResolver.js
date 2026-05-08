const fs = require('fs');
const path = require('path');

function normalizeConfiguredPath(value) {
  if (!value || typeof value !== 'string') return '';

  let normalized = value.trim();
  if (
    (normalized.startsWith('"') && normalized.endsWith('"')) ||
    (normalized.startsWith("'") && normalized.endsWith("'"))
  ) {
    normalized = normalized.slice(1, -1);
  }

  return normalized
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, '\\t');
}

function isPathLike(command) {
  return /[\\/]/.test(command) || path.isAbsolute(command);
}

function resolveToolBin(envName, fallbackCommand, candidatePaths = []) {
  const configured = normalizeConfiguredPath(process.env[envName]);
  const candidates = [configured, ...candidatePaths, fallbackCommand].filter(Boolean);

  for (const candidate of candidates) {
    const resolved = isPathLike(candidate)
      ? path.resolve(process.cwd(), candidate)
      : candidate;

    if (!isPathLike(resolved) || fs.existsSync(resolved)) {
      return resolved;
    }
  }

  return fallbackCommand;
}

module.exports = { normalizeConfiguredPath, resolveToolBin };
