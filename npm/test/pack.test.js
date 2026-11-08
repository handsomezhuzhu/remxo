'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const zlib = require('node:zlib');
const { TARGETS } = require('../lib/targets');
const { mainManifest } = require('../../scripts/npm/manifest');
const { packMain, stageCore, verifyNativeVersion } = require('../../scripts/npm/pack');

const launcherPackage = require('../package.json');

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'remxo-pack-test-'));
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return directory;
}

function stringField(block, offset, length) {
  return block.subarray(offset, offset + length).toString('utf8').replace(/\0.*$/s, '');
}

function numberField(block, offset, length) {
  const value = stringField(block, offset, length).trim();
  return value ? Number.parseInt(value, 8) : 0;
}

function extractNpmTarball(tarball, destination) {
  const archive = zlib.gunzipSync(fs.readFileSync(tarball));
  fs.mkdirSync(destination, { recursive: true });
  for (let offset = 0; offset + 512 <= archive.length;) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) return;
    const name = stringField(header, 0, 100);
    const prefix = stringField(header, 345, 155);
    const archiveName = prefix ? `${prefix}/${name}` : name;
    const size = numberField(header, 124, 12);
    const mode = numberField(header, 100, 8);
    const type = String.fromCharCode(header[156] || 48);
    const contentOffset = offset + 512;
    offset = contentOffset + Math.ceil(size / 512) * 512;
    if (size > archive.length || offset > archive.length) throw new Error('truncated test tarball');
    if (!archiveName.startsWith('package/')) throw new Error(`unexpected npm entry: ${archiveName}`);
    const relative = archiveName.slice('package/'.length);
    const output = path.resolve(destination, relative);
    if (!output.startsWith(`${path.resolve(destination)}${path.sep}`)) {
      throw new Error(`unsafe npm entry: ${archiveName}`);
    }
    if (type === '5') {
      fs.mkdirSync(output, { recursive: true });
    } else if (type === '0') {
      fs.mkdirSync(path.dirname(output), { recursive: true });
      fs.writeFileSync(output, archive.subarray(contentOffset, contentOffset + size));
      fs.chmodSync(output, mode || 0o644);
    } else {
      throw new Error(`unsupported entry in test tarball: ${type} ${archiveName}`);
    }
  }
  throw new Error('test tarball has no end marker');
}

test('release manifests pin every optional core to the identical version', () => {
  const manifest = mainManifest('1.2.3-rc.1');
  assert.equal(manifest.version, '1.2.3-rc.1');
  assert.equal(manifest.scripts, undefined);
  assert.deepEqual(manifest.optionalDependencies, Object.fromEntries(
    Object.values(TARGETS).map((target) => [target.packageName, '1.2.3-rc.1'])
      .sort(([a], [b]) => a.localeCompare(b)),
  ));
  for (const [packageName, version] of Object.entries(launcherPackage.optionalDependencies)) {
    assert.equal(version, launcherPackage.version, packageName);
  }
  assert.throws(() => mainManifest('not-a-version'), /invalid npm package version/);
});

test('native release handshake requires exact remxo --version output', () => {
  const calls = [];
  verifyNativeVersion('native-core', '0.1.0', {
    spawnSync: (...args) => {
      calls.push(args);
      return { status: 0, signal: null, stdout: 'remxo 0.1.0\n', stderr: '' };
    },
  });
  assert.deepEqual(calls[0][0], 'native-core');
  assert.deepEqual(calls[0][1], ['--version']);
  assert.equal(calls[0][2].shell, false);
  assert.throws(() => verifyNativeVersion('native-core', '0.1.0', {
    spawnSync: () => ({ status: 0, signal: null, stdout: 'remxo 0.1.3\n', stderr: '' }),
  }), /package 0\.1\.0, binary 0\.1\.3/);
  assert.throws(() => verifyNativeVersion('native-core', '0.1.0', {
    spawnSync: () => ({ status: 0, signal: null, stdout: 'banner\nremxo 0.1.0\n', stderr: '' }),
  }), /unexpected format/);
});

test('core staging places the native artifact in the Rust target vendor path', (t) => {
  const directory = temporaryDirectory(t);
  const artifact = path.join(directory, 'local remxo.exe');
  fs.writeFileSync(artifact, 'small test fixture');
  fs.chmodSync(artifact, 0o755);
  const destination = path.join(directory, 'package');
  const staged = stageCore(destination, 'win32-x64', artifact, '2.0.0', {
    spawnSync: () => ({ status: 0, signal: null, stdout: 'remxo 2.0.0\n', stderr: '' }),
  });
  assert.equal(staged, path.join(
    destination,
    'vendor',
    'x86_64-pc-windows-msvc',
    'bin',
    'remxo.exe',
  ));
  assert.equal(fs.readFileSync(staged, 'utf8'), 'small test fixture');
  assert.equal(JSON.parse(fs.readFileSync(path.join(destination, 'package.json'))).version, '2.0.0');
  const coreReadme = path.join(__dirname, '..', 'packages', 'win32-x64', 'README.md');
  assert.equal(
    fs.readFileSync(path.join(destination, 'README.md'), 'utf8'),
    fs.readFileSync(coreReadme, 'utf8'),
    'core package must ship its own README',
  );
});

test('every npm package ships a non-trivial README', () => {
  const sources = [
    path.join(__dirname, '..', 'README.md'),
    ...Object.keys(TARGETS).map((platform) => path.join(__dirname, '..', 'packages', platform, 'README.md')),
  ];
  for (const source of sources) {
    const contents = fs.readFileSync(source, 'utf8');
    assert.match(contents, /^# /, `${source} must start with a markdown heading`);
    assert.ok(contents.length > 400, `${source} is too short to be a useful package page`);
    assert.match(contents, /npm install -g remxo(?!@rc)/, `${source} must document the plain install command`);
  }
  for (const manifest of [launcherPackage, ...Object.values(TARGETS).map((target) => (
    require(path.join(__dirname, '..', 'packages', target.key, 'package.json'))
  ))]) {
    assert.ok(manifest.files.includes('README.md'), `${manifest.name} must list README.md in files`);
  }
});

test('packed launcher passes argv and exit status without optional registry access', (t) => {
  const directory = temporaryDirectory(t);
  const env = {
    ...process.env,
    npm_config_cache: path.join(directory, 'npm-cache'),
    npm_config_offline: 'true',
    npm_config_registry: 'http://127.0.0.1:9/',
  };
  const tarball = packMain({ version: launcherPackage.version, output: directory, env });
  const unpacked = path.join(directory, 'unpacked');
  extractNpmTarball(tarball, unpacked);
  const packedManifest = JSON.parse(fs.readFileSync(path.join(unpacked, 'package.json'), 'utf8'));
  assert.deepEqual(packedManifest.optionalDependencies, mainManifest(launcherPackage.version).optionalDependencies);
  assert.ok(fs.statSync(path.join(unpacked, 'bin', 'remxo.js')).isFile());
  assert.ok(fs.statSync(path.join(unpacked, 'lib', 'launch.js')).isFile());
  assert.ok(packedManifest.files.includes('README.md'), 'packed launcher must list README.md in files');
  assert.match(
    fs.readFileSync(path.join(unpacked, 'README.md'), 'utf8'),
    /^# remxo/,
    'packed launcher must ship its README for the npm package page',
  );
  assert.equal(fs.existsSync(path.join(unpacked, 'node_modules')), false);

  const expected = ['fixture.js', '--json', 'space separated', '中文🚀', 'double" and single\' quotes', 'trailing\\'];
  const result = childProcess.spawnSync(process.execPath, [
    path.join(unpacked, 'bin', 'remxo.js'),
    '--eval',
    'process.stdout.write(JSON.stringify(process.argv.slice(1)));process.exitCode=23',
    ...expected,
  ], {
    encoding: 'utf8',
    env: { ...env, REMXO_CORE_PATH: process.execPath },
    shell: false,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 23, result.stderr);
  const actual = JSON.parse(result.stdout);
  assert.deepEqual(actual, expected);
  if (process.platform === 'win32') assert.equal(result.stderr, '');
  else assert.doesNotMatch(result.stderr, /npm packaging failed|^remxo: /m);
});
