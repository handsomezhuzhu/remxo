'use strict';

const TARGETS = Object.freeze({
  'win32-x64': Object.freeze({
    key: 'win32-x64',
    packageName: '@remxo/core-win32-x64',
    rustTarget: 'x86_64-pc-windows-msvc',
    executable: 'remxo.exe',
    os: 'win32',
    cpu: 'x64',
  }),
  'linux-x64': Object.freeze({
    key: 'linux-x64',
    packageName: '@remxo/core-linux-x64',
    rustTarget: 'x86_64-unknown-linux-gnu',
    executable: 'remxo',
    os: 'linux',
    cpu: 'x64',
    libc: 'glibc',
  }),
  'darwin-x64': Object.freeze({
    key: 'darwin-x64',
    packageName: '@remxo/core-darwin-x64',
    rustTarget: 'x86_64-apple-darwin',
    executable: 'remxo',
    os: 'darwin',
    cpu: 'x64',
  }),
  'darwin-arm64': Object.freeze({
    key: 'darwin-arm64',
    packageName: '@remxo/core-darwin-arm64',
    rustTarget: 'aarch64-apple-darwin',
    executable: 'remxo',
    os: 'darwin',
    cpu: 'arm64',
  }),
});

function resolveTarget(platform = process.platform, arch = process.arch) {
  const key = `${platform}-${arch}`;
  const target = TARGETS[key];
  if (!target) {
    throw new Error(`unsupported platform: ${key}; install a native remxo build instead`);
  }
  return target;
}

module.exports = { TARGETS, resolveTarget };
