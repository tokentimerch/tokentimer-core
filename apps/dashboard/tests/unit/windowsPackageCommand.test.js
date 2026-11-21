import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { buildPackageCommand } from '../../src/components/onboarding/certopsConfig.js';

const windowsIt = process.platform === 'win32' ? it : it.skip;
function runCommand(kind, architecture, hostArchitecture = '') {
  const prefix = `$ErrorActionPreference = 'Stop'\n$env:PROCESSOR_ARCHITECTURE = '${architecture}'\n$env:PROCESSOR_ARCHITEW6432 = '${hostArchitecture}'\nfunction Read-Host { param($Prompt) '${kind}' }\nfunction Invoke-WebRequest { throw 'DOWNLOAD_REACHED' }\n`;
  return spawnSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      prefix + buildPackageCommand('windows'),
    ],
    {
      encoding: 'utf8',
      timeout: 15000,
      windowsHide: true,
    }
  );
}

describe('Windows package command', () => {
  for (const architecture of ['AMD64', 'ARM64']) {
    windowsIt(
      `blocks the ${architecture} bundled package before download`,
      () => {
        const result = runCommand('bundled', architecture);
        expect(result.status).not.toBe(0);
        expect(result.stderr).toContain('requires publisher verification');
        expect(result.stderr).not.toContain('DOWNLOAD_REACHED');
      }
    );
  }
  windowsIt('detects a 64-bit host from a 32-bit shell', () => {
    const result = runCommand('bundled', 'x86', 'AMD64');
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('requires publisher verification');
    expect(result.stderr).not.toContain('DOWNLOAD_REACHED');
  });
  windowsIt('rejects an unsupported architecture before download', () => {
    const result = runCommand('bundled', 'x86');
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('Unsupported Windows architecture');
    expect(result.stderr).not.toContain('DOWNLOAD_REACHED');
  });
  windowsIt('retains the existing legacy download path', () => {
    const result = runCommand('legacy', 'AMD64');
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('DOWNLOAD_REACHED');
  });
});
