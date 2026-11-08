'use strict';

const childProcess = require('node:child_process');
const { resolveCore } = require('./core');

const SIGNAL_NUMBERS = Object.freeze({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15, SIGBREAK: 21 });

function reportFailure(error, processObject = process) {
  const message = error && error.message ? error.message : String(error);
  processObject.stderr.write(`remxo: ${message}\n`);
  processObject.exitCode = 1;
}

function supervise(child, processObject = process) {
  const names = processObject.platform === 'win32'
    ? ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGBREAK']
    : ['SIGINT', 'SIGTERM', 'SIGHUP'];
  const handlers = new Map();
  let settled = false;

  const cleanup = () => {
    for (const [signal, handler] of handlers) {
      processObject.removeListener(signal, handler);
    }
    handlers.clear();
  };

  for (const signal of names) {
    const handler = () => {
      if (child.exitCode === null && child.signalCode === null) {
        try {
          child.kill(signal);
        } catch {
          // The child may have exited between the state check and kill.
        }
      }
    };
    handlers.set(signal, handler);
    processObject.on(signal, handler);
  }

  child.once('error', (error) => {
    if (settled) return;
    settled = true;
    cleanup();
    reportFailure(error, processObject);
  });

  child.once('exit', (code, signal) => {
    if (settled) return;
    settled = true;
    cleanup();
    if (signal) {
      processObject.exitCode = 128 + (SIGNAL_NUMBERS[signal] || 0);
      if (processObject.platform !== 'win32') {
        try {
          processObject.kill(processObject.pid, signal);
        } catch {
          // Keep the conventional signal exit status if self-signalling is unavailable.
        }
      }
    } else {
      processObject.exitCode = code === null ? 1 : code;
    }
  });

  return child;
}

function execute(binaryPath, argv, options = {}) {
  const processObject = options.processObject || process;
  const spawn = options.spawn || childProcess.spawn;
  const canExecve = processObject.platform !== 'win32'
    && processObject.platform !== 'os400'
    && typeof processObject.execve === 'function';

  if (canExecve) {
    processObject.execve(binaryPath, [binaryPath, ...argv], processObject.env);
    return null;
  }

  const child = spawn(binaryPath, argv, {
    env: processObject.env,
    shell: false,
    stdio: 'inherit',
    windowsHide: false,
  });
  return supervise(child, processObject);
}

function launch(argv = process.argv.slice(2), options = {}) {
  const core = resolveCore(options);
  return execute(core.binaryPath, argv, options);
}

module.exports = { execute, launch, reportFailure, supervise };
