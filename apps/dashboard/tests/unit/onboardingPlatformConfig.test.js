import { it as test } from 'vitest';
import assert from 'node:assert/strict';
import { chooseInfrastructure } from '../../src/components/onboarding/certopsScope.js';
import { buildAutomateConfig } from '../../src/components/onboarding/certopsConfig.js';

const linux = {
  objective: 'automate', infrastructure: 'linux', reloadService: 'nginx',
  certPath: '/etc/ssl/server/fullchain.pem', directories: '/etc/ssl/certs',
  acmeClientPath: '/usr/local/bin/certbot', configReviewed: true,
  names: 'web.example.com', zone: 'example.com', dnsProvider: 'cloudflare',
};

test('Linux to Windows drops host-specific config and permits a new Windows config', () => {
  const windows = chooseInfrastructure(linux, 'automate', 'windows');
  for (const key of ['reloadService', 'certPath', 'directories', 'acmeClientPath', 'configReviewed']) {
    assert.equal(windows[key], undefined, key);
  }
  assert.equal(windows.names, linux.names);
  const result = buildAutomateConfig({
    ...windows, os: 'windows', names: ['web.example.com'],
    certPath: 'C:\\TokenTimer\\certs\\server.pem', acmeClientPath: 'C:\\acme.sh\\acme.sh',
    acmeShellPath: 'C:\\Program Files\\Git\\bin\\bash.exe',
  });
  assert.equal(result.ok, true, JSON.stringify(result.fieldErrors));
});

test('Windows to Linux drops IIS configuration and Windows paths', () => {
  const result = chooseInfrastructure({ ...linux, infrastructure: 'windows',
    iisSite: 'Default Web Site', iisPort: '443', sniHost: 'web.example.com',
    acmeShellPath: 'C:\\Git\\bash.exe' }, 'automate', 'linux');
  for (const key of ['iisSite', 'iisPort', 'sniHost', 'acmeShellPath', 'certPath']) assert.equal(result[key], undefined, key);
});

test('choosing the same platform retains reviewed configuration', () => {
  const result = chooseInfrastructure(linux, 'automate', 'linux');
  assert.equal(result.reloadService, 'nginx');
  assert.equal(result.certPath, linux.certPath);
  assert.equal(result.configReviewed, true);
});
