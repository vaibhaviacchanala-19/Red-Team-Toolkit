const dns = require('dns').promises;
const validator = require('../utils/validator');

const commonSubdomains = [
  'www', 'api', 'dev', 'test', 'mail', 'staging', 'blog', 'admin', 
  'shop', 'portal', 'vpn', 'remote', 'support', 'docs', 'cdn', 'status',
  'auth', 'sso', 'assets', 'files', 'owa', 'git'
];

async function enumerateSubdomains(domain) {
  if (validator.isIP(domain)) return [];

  const discovered = [];
  
  const tasks = commonSubdomains.map(async (sub) => {
    const fullDomain = `${sub}.${domain}`;
    try {
      const addresses = await dns.resolve4(fullDomain);
      if (addresses.length > 0) {
        discovered.push({
          subdomain: fullDomain,
          ip: addresses[0]
        });
      }
    } catch (error) {
      // Subdomain doesn't exist
    }
  });

  await Promise.all(tasks);
  return discovered;
}

module.exports = { enumerateSubdomains };
