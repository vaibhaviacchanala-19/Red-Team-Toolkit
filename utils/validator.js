const dns = require('dns').promises;
const net = require('net');
const validator = require('validator');

const MAX_TARGET_LENGTH = 253;

function stripProtocolAndPath(rawTarget) {
  const value = String(rawTarget || '').trim().toLowerCase();
  if (!value) return '';

  try {
    const withProtocol = /^https?:\/\//i.test(value) ? value : `https://${value}`;
    const parsed = new URL(withProtocol);
    return parsed.hostname.replace(/\.$/, '');
  } catch (error) {
    return value.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].replace(/\.$/, '');
  }
}

function isValidTarget(target) {
  const normalized = stripProtocolAndPath(target);
  if (!normalized || normalized.length > MAX_TARGET_LENGTH) return false;
  if (/[^a-z0-9.:-]/i.test(normalized)) return false;
  return validator.isFQDN(normalized, { require_tld: true }) || validator.isIP(normalized);
}

function ipv4ToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

function inRange(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = bits === '0' ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
  return (ipv4ToLong(ip) & mask) === (ipv4ToLong(range) & mask);
}

function isPrivateIP(ip) {
  if (!ip) return true;

  if (net.isIPv4(ip)) {
    return [
      '0.0.0.0/8',
      '10.0.0.0/8',
      '100.64.0.0/10',
      '127.0.0.0/8',
      '169.254.0.0/16',
      '172.16.0.0/12',
      '192.0.0.0/24',
      '192.0.2.0/24',
      '192.168.0.0/16',
      '198.18.0.0/15',
      '198.51.100.0/24',
      '203.0.113.0/24',
      '224.0.0.0/4',
      '240.0.0.0/4'
    ].some((cidr) => inRange(ip, cidr));
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    return lower === '::1'
      || lower === '::'
      || lower.startsWith('fc')
      || lower.startsWith('fd')
      || lower.startsWith('fe80:')
      || lower.startsWith('ff')
      || lower.startsWith('2001:db8:');
  }

  return true;
}

async function resolveTarget(target) {
  const normalized = stripProtocolAndPath(target);

  if (!isValidTarget(normalized)) {
    const error = new Error('Invalid target. Provide a public domain or IP address.');
    error.status = 400;
    throw error;
  }

  const addresses = validator.isIP(normalized)
    ? [normalized]
    : await Promise.race([
      dns.lookup(normalized, { all: true, verbatim: false }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('DNS lookup timed out')), 6000))
    ]).then((records) => records.map((record) => record.address));

  const uniqueAddresses = [...new Set(addresses)];
  if (uniqueAddresses.length === 0) {
    const error = new Error('Target resolution failed.');
    error.status = 400;
    throw error;
  }

  const restricted = uniqueAddresses.find((ip) => isPrivateIP(ip));
  if (restricted) {
    const error = new Error(`Target resolves to a private, reserved, or restricted IP address (${restricted}).`);
    error.status = 400;
    throw error;
  }

  return {
    target: normalized,
    scanUrl: `https://${normalized}`,
    ip: uniqueAddresses[0],
    addresses: uniqueAddresses
  };
}

module.exports = {
  stripProtocolAndPath,
  isValidTarget,
  isPrivateIP,
  resolveTarget,
  getSafeIP: async (target) => (await resolveTarget(target)).ip,
  isIP: (value) => Boolean(validator.isIP(value))
};
