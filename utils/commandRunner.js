const { spawn } = require('child_process');

function runCommand(command, args, options = {}) {
  const timeoutMs = options.timeoutMs || 30000;

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const child = spawn(command, args, {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      resolve({
        ok: false,
        code: null,
        timedOut: true,
        stdout,
        stderr,
        durationMs: Date.now() - startedAt
      });
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        ok: false,
        code: null,
        error,
        stdout,
        stderr,
        durationMs: Date.now() - startedAt
      });
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        ok: code === 0,
        code,
        stdout,
        stderr,
        durationMs: Date.now() - startedAt
      });
    });
  });
}

module.exports = { runCommand };
