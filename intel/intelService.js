const axios = require('axios');
const logger = require('../utils/logger');

async function checkVirusTotal(target) {
  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) {
    return { status: 'unavailable', provider: 'VirusTotal', summary: 'VirusTotal API key not configured' };
  }

  try {
    const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
    const endpoint = isIP ? 'ip_addresses' : 'domains';
    const url = `https://www.virustotal.com/api/v3/${endpoint}/${target}`;
    const response = await axios.get(url, {
      headers: { 'x-apikey': apiKey },
      timeout: 9000
    });

    const attr = response.data?.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};

    return {
      status: 'success',
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      reputation: attr.reputation ?? 0,
      asn: attr.as_owner || 'N/A',
      country: attr.country || 'Unknown',
      categories: attr.categories || {},
      maliciousDetails: attr.last_analysis_results || {},
      summary: `${stats.malicious || 0} malicious and ${stats.suspicious || 0} suspicious detections`
    };
  } catch (error) {
    const status = error.response?.status;
    const message = error.response?.data?.error?.message || error.message;
    logger.error(`[Intel] VirusTotal fail: ${message}`);
    return {
      status: 'unavailable',
      reason: status === 401 ? 'Invalid API Key' : status === 429 ? 'Rate Limit' : 'API failure',
      error: message
    };
  }
}

async function checkAbuseIPDB(ip) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return { status: 'unavailable', provider: 'AbuseIPDB', summary: 'AbuseIPDB API key not configured' };
  }

  if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) {
    return { status: 'error', error: 'Valid IPv4 address required' };
  }

  try {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: apiKey, Accept: 'application/json' },
      timeout: 9000
    });

    const data = response.data?.data || {};
    return {
      status: 'success',
      abuseScore: data.abuseConfidenceScore || 0,
      totalReports: data.totalReports || 0,
      country: data.countryCode || 'Unknown',
      usageType: data.usageType || 'Unknown',
      isp: data.isp || 'Unknown',
      domain: data.domain || 'Unknown',
      hostnames: data.hostnames || [],
      summary: `${data.abuseConfidenceScore || 0}% abuse confidence across ${data.totalReports || 0} reports`
    };
  } catch (error) {
    const status = error.response?.status;
    const message = error.response?.data?.errors?.[0]?.detail || error.message;
    logger.error(`[Intel] AbuseIPDB fail: ${message}`);
    return {
      status: 'unavailable',
      reason: status === 401 ? 'Invalid API Key' : status === 429 ? 'Rate Limit' : 'API failure',
      error: message
    };
  }
}

module.exports = { checkVirusTotal, checkAbuseIPDB };
