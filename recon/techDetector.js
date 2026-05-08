/**
 * Professional Technology Detector
 * Identifies frameworks, servers, CMS, and WAFs using deep fingerprinting.
 */
function detectTech(headers) {
  const techs = new Set();
  const h = Object.keys(headers).reduce((acc, key) => {
    const value = headers[key];
    acc[key.toLowerCase()] = Array.isArray(value)
      ? value.join(', ').toLowerCase()
      : String(value || '').toLowerCase();
    return acc;
  }, {});

  // 1. Web Servers
  const server = h['server'] || '';
  if (server.includes('apache')) techs.add('Apache HTTP Server');
  if (server.includes('nginx')) techs.add('Nginx');
  if (server.includes('microsoft-iis')) techs.add('Microsoft IIS');
  if (server.includes('litespeed')) techs.add('LiteSpeed');
  if (server.includes('google')) techs.add('Google Web Server');

  // 2. Languages & Frameworks
  const powered = h['x-powered-by'] || '';
  if (powered.includes('php')) techs.add('PHP');
  if (powered.includes('express') || powered.includes('node')) techs.add('Node.js (Express)');
  if (powered.includes('asp.net')) techs.add('ASP.NET');
  if (h['x-nextjs-cache']) techs.add('Next.js');
  if (h['x-aspnet-version']) techs.add('ASP.NET');

  // 3. CMS Detection
  const generator = h['x-generator'] || '';
  if (generator.includes('wordpress') || h['x-wp-cf-cache']) techs.add('WordPress');
  if (generator.includes('drupal')) techs.add('Drupal');
  if (generator.includes('joomla')) techs.add('Joomla');
  if (generator.includes('magento')) techs.add('Magento');
  if (generator.includes('shopify') || h['x-shopify-stage']) techs.add('Shopify');

  // 4. WAF & CDN Detection
  if (h['x-cdn'] === 'incapsula' || h['x-iinfo']) techs.add('Imperva WAF');
  if (h['server'] === 'cloudflare' || h['cf-ray']) techs.add('Cloudflare WAF/CDN');
  if (h['x-akamai-transformed']) techs.add('Akamai CDN');
  if (h['x-vcloud-id']) techs.add('Verizon CDN');

  // 5. JavaScript Libraries (via common headers)
  if (h['x-react-version'] || h['x-react-helmet']) techs.add('React.js');

  return Array.from(techs);
}

module.exports = { detectTech };
