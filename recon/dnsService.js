const dns = require('dns').promises;
const whois = require('whois-json');
const validator = require('../utils/validator');

async function getDNSInfo(target) {
  const info = {
    a: [],
    mx: [],
    ns: [],
    txt: []
  };

  try {
    if (validator.isIP(target)) {
      info.a = [target];
      return info;
    }

    info.a = await dns.resolve4(target).catch(() => []);
    info.aaaa = await dns.resolve6(target).catch(() => []);
    info.mx = await dns.resolveMx(target).catch(() => []);
    info.ns = await dns.resolveNs(target).catch(() => []);
    info.txt = await dns.resolveTxt(target).catch(() => []);
    info.cname = await dns.resolveCname(target).catch(() => []);
  } catch (error) {
    info.error = error.message;
  }

  return info;
}

async function getWhoisInfo(target) {
  try {
    if (validator.isIP(target)) {
      return { error: 'WHOIS lookup requires a hostname, not an IP address.' };
    }

    const data = await Promise.race([
      whois(target),
      new Promise((_, reject) => setTimeout(() => reject(new Error('WHOIS lookup timed out')), Number(process.env.WHOIS_TIMEOUT_MS || 7000)))
    ]);
    return {
      registrar: data.registrar || data.registrarName || 'Unknown',
      creationDate: data.creationDate || data.createdDate || 'Unknown',
      expirationDate: data.expirationDate || data.expiryDate || 'Unknown',
      organization: data.registrantOrganization || data.org || 'Unknown'
    };
  } catch (error) {
    return { error: error.message || 'Whois data not available' };
  }
}

module.exports = {
  getDNSInfo,
  getWhoisInfo
};
