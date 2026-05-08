const net = require('net');

// Common 1000 ports (shorthand for demo - in production use a full list)
const commonPorts = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443
];

// Fill with more ports to simulate "top 1000"
for (let i = 1; i <= 1000; i++) {
  if (!commonPorts.includes(i)) {
    if (i % 10 === 0) commonPorts.push(i);
  }
}

async function scanPort(host, port, timeout = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = 'closed';

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      status = 'open';
      socket.destroy();
    });

    socket.on('timeout', () => {
      socket.destroy();
    });

    socket.on('error', () => {
      socket.destroy();
    });

    socket.on('close', () => {
      resolve({ port, status });
    });

    socket.connect(port, host);
  });
}

/**
 * Manual concurrency-limited scan to avoid dependency issues
 */
async function scanPorts(host) {
  const concurrency = 50;
  const results = [];
  const ports = [...commonPorts];

  async function worker() {
    while (ports.length > 0) {
      const port = ports.shift();
      const res = await scanPort(host, port);
      if (res.status === 'open') {
        results.push(res);
      }
    }
  }

  const workers = Array(concurrency).fill(null).map(() => worker());
  await Promise.all(workers);
  
  return results;
}

module.exports = { scanPorts };
