const dns = require('dns').promises;
const net = require('net');
const logger = require('../utils/logger');
const { isPrivateIP, isIP, stripProtocolAndPath } = require('../utils/validator');

const DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 8080, 8443];

const SERVICE_NAMES = {
  21: 'ftp',
  22: 'ssh',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  110: 'pop3',
  143: 'imap',
  443: 'https',
  445: 'smb',
  587: 'smtp-submission',
  993: 'imaps',
  995: 'pop3s',
  3306: 'mysql',
  3389: 'rdp',
  8080: 'http-alt',
  8443: 'https-alt'
};

async function scanPorts(rawTarget) {
  const target = stripProtocolAndPath(rawTarget);
  const timeoutMs = Number(process.env.PORT_SCAN_TIMEOUT_MS || process.env.NMAP_TIMEOUT_MS || 3500);
  const retries = Number(process.env.PORT_SCAN_RETRIES || 1);
  const concurrency = Number(process.env.PORT_SCAN_CONCURRENCY || 8);
  const portsToScan = parsePorts(process.env.PORT_SCAN_PORTS || process.env.NMAP_PORTS) || DEFAULT_PORTS;

  logger.info(`[SCAN] Resolving ${target} for TCP port scan`);
  const resolved = await resolveScanAddresses(target);

  if (!resolved.addresses.length) {
    logger.warn(`[SCAN] DNS resolution failed for ${target}`);
    return {
      scanner: 'node-tcp',
      status: 'unavailable',
      ports: [],
      results: [],
      addresses: [],
      rawSummary: 'DNS resolution failed before TCP port scan.'
    };
  }

  logger.info(`[SCAN] ${target} resolved to ${resolved.addresses.join(', ')}`);
  const results = await runQueue(
    portsToScan.map((port) => () => scanPortAcrossAddresses(target, resolved.addresses, port, timeoutMs, retries)),
    concurrency
  );

  const sortedResults = results.sort((a, b) => Number(a.port) - Number(b.port));
  const openPorts = sortedResults.filter((result) => result.status === 'open').map(toOpenPort);

  logger.success(`[SCAN] TCP scan completed for ${target}: ${openPorts.length} open, ${countStatus(sortedResults, 'filtered')} filtered, ${countStatus(sortedResults, 'closed')} closed`);

  return {
    scanner: 'node-tcp',
    status: 'completed',
    ports: openPorts,
    results: sortedResults,
    addresses: resolved.addresses,
    rawSummary: `Scanned ${sortedResults.length} common TCP ports with ${timeoutMs}ms timeout and ${retries} retry attempt(s).`
  };
}

async function resolveScanAddresses(target) {
  if (isIP(target)) {
    if (isPrivateIP(target)) {
      const error = new Error(`Refusing to scan private or restricted IP address ${target}`);
      error.status = 400;
      throw error;
    }
    return { addresses: [target] };
  }

  const records = await dns.lookup(target, { all: true, verbatim: false });
  const addresses = [...new Set(records.map((record) => record.address))]
    .filter((address) => net.isIP(address))
    .filter((address) => !isPrivateIP(address));

  const ipv4 = addresses.filter((address) => net.isIPv4(address));
  const ipv6 = addresses.filter((address) => net.isIPv6(address));
  return { addresses: [...ipv4, ...ipv6] };
}

async function scanPortAcrossAddresses(target, addresses, port, timeoutMs, retries) {
  logger.info(`[SCAN] Testing port ${port} on ${target}`);
  let bestResult = null;

  for (const address of addresses) {
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      const result = await probePort(address, port, timeoutMs);
      const enriched = {
        port,
        status: result.status,
        state: result.status,
        service: getServiceName(port),
        protocol: 'tcp',
        responseTime: result.responseTime,
        address,
        error: result.error || ''
      };

      if (result.status === 'open') {
        logger.success(`[OPEN] Port ${port} reachable on ${target} (${address}) in ${result.responseTime}ms`);
        return enriched;
      }

      if (result.status === 'closed') {
        logger.info(`[CLOSED] Port ${port} refused on ${target} (${address})`);
      } else {
        logger.warn(`[TIMEOUT] Port ${port} filtered on ${target} (${address})`);
      }

      bestResult = chooseBestResult(bestResult, enriched);
      if (result.status === 'closed') break;
    }
  }

  return bestResult || {
    port,
    status: 'filtered',
    state: 'filtered',
    service: getServiceName(port),
    protocol: 'tcp',
    responseTime: timeoutMs,
    address: addresses[0] || '',
    error: 'No connection result'
  };
}

function probePort(address, port, timeoutMs) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const socket = new net.Socket();
    let settled = false;

    const finish = (status, error = '') => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve({
        status,
        error,
        responseTime: Date.now() - startedAt
      });
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish('open'));
    socket.once('timeout', () => finish('filtered', 'timeout'));
    socket.once('error', (error) => {
      const code = error.code || '';
      if (code === 'ECONNREFUSED') {
        finish('closed', code);
        return;
      }
      finish('filtered', code || error.message);
    });

    socket.connect({ host: address, port, family: net.isIPv6(address) ? 6 : 4 });
  });
}

async function runQueue(tasks, concurrency) {
  const results = [];
  let nextIndex = 0;
  const workerCount = Math.max(1, Math.min(Number(concurrency) || 1, tasks.length));

  async function worker() {
    while (nextIndex < tasks.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await tasks[index]();
    }
  }

  await Promise.all(Array.from({ length: workerCount }, worker));
  return results;
}

function chooseBestResult(current, candidate) {
  if (!current) return candidate;
  const rank = { open: 3, closed: 2, filtered: 1 };
  return rank[candidate.status] > rank[current.status] ? candidate : current;
}

function toOpenPort(result) {
  return {
    port: result.port,
    protocol: result.protocol || 'tcp',
    state: 'open',
    status: 'open',
    service: result.service || getServiceName(result.port),
    product: '',
    version: 'unknown',
    responseTime: result.responseTime,
    address: result.address,
    source: 'node-tcp'
  };
}

function parsePorts(value) {
  if (!value) return null;
  const ports = String(value)
    .split(',')
    .map((port) => Number(port.trim()))
    .filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);

  return ports.length ? [...new Set(ports)] : null;
}

function countStatus(results, status) {
  return results.filter((result) => result.status === status).length;
}

function getServiceName(port) {
  return SERVICE_NAMES[Number(port)] || 'unknown';
}

module.exports = { scanPorts };
