'use strict';

const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { assertCoreFile } = require('../../npm/lib/core');
const { TARGETS } = require('../../npm/lib/targets');
const { NPM_DIR, coreManifest, mainManifest, writeManifest } = require('./manifest');

function findNpmCli(env = process.env) {
  const candidates = [];
  if (env.npm_execpath) candidates.push(path.resolve(env.npm_execpath));
  const nodeDir = path.dirname(process.execPath);
  candidates.push(
    path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.resolve(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  );
  for (const candidate of candidates) {
    if (/\.(?:c?js|mjs)$/i.test(candidate) && fs.existsSync(candidate)) return candidate;
  }
  throw new Error('cannot locate npm-cli.js in the active Node.js installation');
}

function packDirectory(packageDirectory, outputDirectory, options = {}) {
  const output = path.resolve(outputDirectory);
  fs.mkdirSync(output, { recursive: true });
  const result = childProcess.spawnSync(process.execPath, [
    options.npmCli || findNpmCli(options.env),
    'pack',
    packageDirectory,
    '--pack-destination',
    output,
    '--json',
    '--ignore-scripts',
  ], {
    encoding: 'utf8',
    env: options.env || process.env,
    maxBuffer: 4 * 1024 * 1024,
    shell: false,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`npm pack failed: ${result.error?.message || result.stderr || `exit ${result.status}`}`);
  }
  let details;
  try {
    details = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error('npm pack returned invalid JSON', { cause: error });
  }
  const filename = details[0]?.filename;
  if (!filename || path.basename(filename) !== filename) {
    throw new Error('npm pack returned an invalid tarball path');
  }
  const tarball = path.join(output, filename);
  if (!fs.statSync(tarball).isFile()) throw new Error(`npm tarball was not created: ${tarball}`);
  return tarball;
}

function verifyNativeVersion(binaryPath, expectedVersion, options = {}) {
  const spawnSync = options.spawnSync || childProcess.spawnSync;
  const result = spawnSync(binaryPath, ['--version'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
    windowsHide: true,
  });
  if (result.error || result.status !== 0 || result.signal) {
    throw new Error(`native remxo --version failed: ${result.error?.message || result.stderr || result.status || result.signal}`);
  }
  const match = /^remxo ([^\r\n]+)\r?\n?$/.exec(result.stdout);
  if (!match) throw new Error('native remxo --version returned an unexpected format');
  if (match[1] !== expectedVersion) {
    throw new Error(`native core version mismatch: package ${expectedVersion}, binary ${match[1]}`);
  }
}

function stageMain(directory, version) {
  writeManifest(directory, mainManifest(version));
  for (const name of ['bin', 'lib']) {
    fs.cpSync(path.join(NPM_DIR, name), path.join(directory, name), { recursive: true });
  }
}

function stageCore(directory, platform, artifact, version, options = {}) {
  const target = TARGETS[platform];
  if (!target) throw new Error(`unsupported package target: ${platform}`);
  writeManifest(directory, coreManifest(platform, version));
  const source = assertCoreFile(path.resolve(artifact), process.platform);
  verifyNativeVersion(source, version, options);
  const destination = path.join(directory, 'vendor', target.rustTarget, 'bin', target.executable);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  fs.chmodSync(destination, 0o755);
  return destination;
}

function packMain(options) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'remxo-npm-main-'));
  try {
    const directory = path.join(work, 'package');
    stageMain(directory, options.version);
    return packDirectory(directory, options.output, options);
  } finally {
    fs.rmSync(work, { force: true, recursive: true });
  }
}

function packCore(options) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), `remxo-npm-${options.platform}-`));
  try {
    const directory = path.join(work, 'package');
    stageCore(directory, options.platform, options.artifact, options.version, options);
    return packDirectory(directory, options.output, options);
  } finally {
    fs.rmSync(work, { force: true, recursive: true });
  }
}

function parseArguments(argv) {
  const options = {
    main: false,
    version: readManifestVersion(),
    output: path.join(NPM_DIR, 'dist'),
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--main') options.main = true;
    else if (argument === '--help' || argument === '-h') options.help = true;
    else {
      const names = {
        '--platform': 'platform',
        '--artifact': 'artifact',
        '--version': 'version',
        '--out': 'output',
        '--output': 'output',
      };
      const name = names[argument];
      if (!name) throw new Error(`unknown argument: ${argument}`);
      if (index + 1 >= argv.length || argv[index + 1] === '') {
        throw new Error(`missing value for ${argument}`);
      }
      options[name] = argv[++index];
    }
  }
  if (!options.version || !options.output) throw new Error('version and output directory must not be empty');
  return options;
}

function readManifestVersion() {
  return JSON.parse(fs.readFileSync(path.join(NPM_DIR, 'package.json'), 'utf8')).version;
}

function usage() {
  return [
    'Pack the launcher:',
    '  node scripts/npm/pack.js --main --out <directory>',
    'Pack one native core on its matching host:',
    '  node scripts/npm/pack.js --platform <win32-x64|linux-x64> --artifact <remxo binary> --out <directory>',
  ].join('\n');
}

function run(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (options.main === Boolean(options.platform)) {
    throw new Error('choose exactly one of --main or --platform');
  }
  if (options.main) {
    if (options.artifact) throw new Error('--artifact is only valid with --platform');
    process.stdout.write(`${packMain(options)}\n`);
  } else {
    if (!TARGETS[options.platform]) throw new Error(`unsupported package target: ${options.platform}`);
    if (!options.artifact) throw new Error('--artifact is required with --platform');
    process.stdout.write(`${packCore(options)}\n`);
  }
}

if (require.main === module) {
  try {
    run();
  } catch (error) {
    process.stderr.write(`npm packaging failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  findNpmCli,
  packCore,
  packDirectory,
  packMain,
  parseArguments,
  stageCore,
  stageMain,
  verifyNativeVersion,
};
