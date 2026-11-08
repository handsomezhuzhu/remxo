'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { LauncherError, resolveCore } = require('../lib/core');
const { execute } = require('../lib/launch');
const { TARGETS, resolveTarget } = require('../lib/targets');

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'remxo-launcher-test-'));
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return directory;
}

function coreFixture(directory, version = '0.1.0') {
  const target = TARGETS['win32-x64'];
  const launcherManifestPath = path.join(directory, 'package.json');
  fs.writeFileSync(launcherManifestPath, JSON.stringify({ name: 'remxo', version: '0.1.0' }));
  const packageRoot = path.join(directory, 'node_modules', '@remxo', 'core-win32-x64');
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({
    name: target.packageName,
    version,
    os: ['win32'],
    cpu: ['x64'],
  }));
  const binaryPath = path.join(packageRoot, 'vendor', target.rustTarget, 'bin', target.executable);
  fs.mkdirSync(path.dirname(binaryPath), { recursive: true });
  fs.writeFileSync(binaryPath, 'test fixture, not an executable');
  return { binaryPath, launcherManifestPath };
}

test('target mappings cover exactly the four declared native packages', () => {
  assert.deepEqual(Object.keys(TARGETS).sort(), [
    'darwin-arm64',
    'darwin-x64',
    'linux-x64',
    'win32-x64',
  ]);
  assert.equal(resolveTarget('win32', 'x64').rustTarget, 'x86_64-pc-windows-msvc');
  assert.equal(resolveTarget('linux', 'x64').rustTarget, 'x86_64-unknown-linux-gnu');
  assert.equal(resolveTarget('linux', 'x64').libc, 'glibc');
  assert.equal(resolveTarget('darwin', 'x64').rustTarget, 'x86_64-apple-darwin');
  assert.equal(resolveTarget('darwin', 'arm64').rustTarget, 'aarch64-apple-darwin');
  assert.throws(() => resolveTarget('linux', 'arm64'), /unsupported platform/);
  assert.throws(() => resolveTarget('win32', 'arm64'), /unsupported platform/);
  assert.throws(() => resolveTarget('freebsd', 'x64'), /unsupported platform/);
});

test('missing optional package fails closed', (t) => {
  const directory = temporaryDirectory(t);
  const launcherManifestPath = path.join(directory, 'package.json');
  fs.writeFileSync(launcherManifestPath, JSON.stringify({ name: 'remxo', version: '0.1.0' }));
  assert.throws(
    () => resolveCore({ platform: 'win32', arch: 'x64', env: {}, launcherManifestPath }),
    (error) => error instanceof LauncherError
      && /missing @remxo\/core-win32-x64@0\.1\.0/.test(error.message)
      && error.cause?.code === 'MODULE_NOT_FOUND',
  );
});

test('platform package version must exactly match the launcher', (t) => {
  const fixture = coreFixture(temporaryDirectory(t), '0.1.1');
  assert.throws(
    () => resolveCore({
      platform: 'win32',
      arch: 'x64',
      env: {},
      launcherManifestPath: fixture.launcherManifestPath,
    }),
    /native core version mismatch: launcher 0\.1\.0, @remxo\/core-win32-x64 0\.1\.1/,
  );
});

test('resolved package uses its versioned vendor target path', (t) => {
  const fixture = coreFixture(temporaryDirectory(t));
  const core = resolveCore({
    platform: 'win32',
    arch: 'x64',
    env: {},
    launcherManifestPath: fixture.launcherManifestPath,
  });
  assert.equal(core.binaryPath, fixture.binaryPath);
  assert.equal(core.packageVersion, '0.1.0');
});

test('explicit core path never searches PATH and a missing override fails', (t) => {
  const directory = temporaryDirectory(t);
  const file = path.join(directory, 'native core with spaces.exe');
  fs.writeFileSync(file, 'fixture');
  const core = resolveCore({
    platform: 'win32',
    arch: 'x64',
    env: { REMXO_CORE_PATH: file },
    launcherManifestPath: path.join(directory, 'absent-package.json'),
  });
  assert.equal(core.binaryPath, file);
  assert.equal(core.packageVersion, null);
  assert.throws(
    () => resolveCore({ platform: 'win32', arch: 'x64', env: { REMXO_CORE_PATH: 'definitely-not-on-path' } }),
    /native core is missing or not executable/,
  );
  assert.throws(
    () => resolveCore({ platform: 'win32', arch: 'x64', env: { REMXO_CORE_PATH: '' } }),
    /REMXO_CORE_PATH must name a native core file/,
  );
});

test('Unix execve preserves argv0 and user argv', () => {
  const calls = [];
  const processObject = {
    platform: 'linux',
    env: { TEST_VALUE: 'unchanged' },
    execve: (...args) => calls.push(args),
  };
  const argv = ['space separated', '中文🚀', 'double" and single\' quotes', 'trailing\\'];
  const result = execute('/opt/remxo/vendor/native', argv, {
    processObject,
    spawn: () => assert.fail('execve path must not spawn'),
  });
  assert.equal(result, null);
  assert.deepEqual(calls, [[ '/opt/remxo/vendor/native', ['/opt/remxo/vendor/native', ...argv], processObject.env ]]);
});

test('Windows spawn preserves argv, stdio, exit codes, and signal forwarding', () => {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  const forwarded = [];
  child.kill = (signal) => forwarded.push(signal);

  const processObject = new EventEmitter();
  Object.assign(processObject, {
    platform: 'win32',
    env: {},
    pid: 1234,
    stderr: { write: (text) => assert.fail(text) },
  });
  const calls = [];
  const argv = ['--json', 'space separated', '中文🚀', '"quoted"'];
  execute('C:\\vendor\\remxo.exe', argv, {
    processObject,
    spawn: (...args) => {
      calls.push(args);
      return child;
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'C:\\vendor\\remxo.exe');
  assert.deepEqual(calls[0][1], argv);
  assert.deepEqual(calls[0][2], {
    env: processObject.env,
    shell: false,
    stdio: 'inherit',
    windowsHide: false,
  });

  processObject.emit('SIGINT');
  assert.deepEqual(forwarded, ['SIGINT']);
  child.emit('exit', null, 'SIGINT');
  assert.equal(processObject.exitCode, 130);
  assert.equal(processObject.listenerCount('SIGINT'), 0);

  const another = new EventEmitter();
  another.exitCode = null;
  another.signalCode = null;
  another.kill = () => {};
  const result = execute('C:\\vendor\\remxo.exe', [], { processObject, spawn: () => another });
  assert.equal(result, another);
  another.emit('exit', 37, null);
  assert.equal(processObject.exitCode, 37);
});
