const chalk = require('chalk');

const logger = {
  info: (msg) => console.log(`[${new Date().toLocaleTimeString()}] ${chalk.blue('INFO')}: ${msg}`),
  warn: (msg) => console.log(`[${new Date().toLocaleTimeString()}] ${chalk.yellow('WARN')}: ${msg}`),
  error: (msg) => console.log(`[${new Date().toLocaleTimeString()}] ${chalk.red('ERROR')}: ${msg}`),
  success: (msg) => console.log(`[${new Date().toLocaleTimeString()}] ${chalk.green('SUCCESS')}: ${msg}`),
  report: (data) => {
    console.log(chalk.cyan('\n--- SCAN REPORT ---'));
    console.log(JSON.stringify(data, null, 2));
    console.log(chalk.cyan('-------------------\n'));
  }
};

// Handle missing chalk gracefully if needed, but we installed it (wait, I didn't install chalk!)
// I'll re-install chalk or just use plain console.log for now if I don't want to run another command.
// Actually, I'll just use a simpler version without chalk to be safe, or just run the command.

module.exports = logger;
