'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { TARGETS } = require('../../npm/lib/targets');
const { readManifest } = require('../../npm/lib/core');

const ROOT_DIR = path.resolve(__dirname, '..', '..');
const NPM_DIR = path.join(ROOT_DIR, 'npm');
const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function checkedVersion(version) {
  if (!VERSION_PATTERN.test(version || '')) {
    throw new Error(`invalid npm package version: ${version || '(empty)'}`);
  }
  return version;
}

function mainManifest(version) {
  checkedVersion(version);
  const source = readManifest(path.join(NPM_DIR, 'package.json'));
  const manifest = { ...source, version };
  delete manifest.scripts;
  manifest.optionalDependencies = Object.fromEntries(
    Object.values(TARGETS).map((target) => [target.packageName, version]).sort(([a], [b]) => a.localeCompare(b)),
  );
  return manifest;
}

function coreManifest(platform, version) {
  checkedVersion(version);
  const target = TARGETS[platform];
  if (!target) throw new Error(`unsupported package target: ${platform}`);
  const source = readManifest(path.join(NPM_DIR, 'packages', platform, 'package.json'));
  if (source.name !== target.packageName) {
    throw new Error(`template name mismatch for ${platform}: ${source.name}`);
  }
  return { ...source, version };
}

function writeManifest(directory, manifest) {
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
}

module.exports = { NPM_DIR, ROOT_DIR, coreManifest, mainManifest, writeManifest };
