'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { resolveTarget } = require('./targets');

class LauncherError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'LauncherError';
  }
}

function readManifest(file) {
  let value;
  try {
    value = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new LauncherError(`cannot read package manifest: ${file}`, { cause: error });
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new LauncherError(`invalid package manifest: ${file}`);
  }
  return value;
}

function assertCoreFile(file, platform) {
  let stat;
  try {
    stat = fs.statSync(file);
    if (!stat.isFile()) {
      throw new Error('not a regular file');
    }
    if (platform !== 'win32') {
      fs.accessSync(file, fs.constants.X_OK);
    }
  } catch (error) {
    throw new LauncherError(`native core is missing or not executable: ${file}`, { cause: error });
  }
  return fs.realpathSync(file);
}

function supports(manifest, field, value) {
  return Array.isArray(manifest[field]) && manifest[field].includes(value);
}

function resolveCore(options = {}) {
  const platform = options.platform || process.platform;
  const arch = options.arch || process.arch;
  const target = resolveTarget(platform, arch);
  const env = options.env || process.env;

  if (Object.hasOwn(env, 'REMXO_CORE_PATH')) {
    const override = env.REMXO_CORE_PATH;
    if (typeof override !== 'string' || override.length === 0) {
      throw new LauncherError('REMXO_CORE_PATH must name a native core file');
    }
    return {
      binaryPath: assertCoreFile(path.resolve(override), platform),
      target,
      packageVersion: null,
    };
  }

  const launcherManifestPath = options.launcherManifestPath || path.join(__dirname, '..', 'package.json');
  const launcher = readManifest(launcherManifestPath);
  if (typeof launcher.version !== 'string' || launcher.version.length === 0) {
    throw new LauncherError(`launcher has no valid version: ${launcherManifestPath}`);
  }

  const resolve = options.resolvePackage || createRequire(launcherManifestPath).resolve;
  let coreManifestPath;
  try {
    coreManifestPath = resolve(`${target.packageName}/package.json`);
  } catch (error) {
    throw new LauncherError(
      `missing ${target.packageName}@${launcher.version}; reinstall remxo without omitting optional dependencies`,
      { cause: error },
    );
  }

  const core = readManifest(coreManifestPath);
  if (core.name !== target.packageName) {
    throw new LauncherError(`unexpected native core package: ${core.name || '(unnamed)'}`);
  }
  if (core.version !== launcher.version) {
    throw new LauncherError(
      `native core version mismatch: launcher ${launcher.version}, ${target.packageName} ${core.version || '(missing)'}`,
    );
  }
  if (!supports(core, 'os', platform) || !supports(core, 'cpu', arch)) {
    throw new LauncherError(`native core package does not match ${platform}-${arch}`);
  }
  if (target.libc && !supports(core, 'libc', target.libc)) {
    throw new LauncherError(`native core package does not match ${target.libc}`);
  }

  const packageRoot = path.dirname(coreManifestPath);
  const binaryPath = path.join(packageRoot, 'vendor', target.rustTarget, 'bin', target.executable);
  return {
    binaryPath: assertCoreFile(binaryPath, platform),
    target,
    packageVersion: core.version,
  };
}

module.exports = { LauncherError, assertCoreFile, readManifest, resolveCore };
