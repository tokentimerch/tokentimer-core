import { describe, it, expect } from 'vitest';
import { assistantSetupCommand } from '../../src/components/certops/assistantSetupCommand.js';

describe('assistant enrollment commands', () => {
  it('uses the configured prefix or same-origin address without changing shell meaning', () => {
    expect(
      assistantSetupCommand(
        'https://api.example.test/prefix/',
        'https://app.example.test'
      )
    ).toContain('"https://api.example.test/prefix"');
    expect(assistantSetupCommand('', 'https://app.example.test')).toContain(
      '"https://app.example.test"'
    );
    expect(
      assistantSetupCommand('/prefix', 'https://app.example.test')
    ).toContain('"https://app.example.test/prefix"');
    expect(
      assistantSetupCommand(
        'http://127.0.0.1:55510',
        'https://app.example.test'
      )
    ).toContain('127.0.0.1:55510');
  });
  it.each([
    'http://remote.example.test',
    'https://user:password@example.test',
    'https://example.test/?secret=x',
    'https://example.test/#code',
    'https://example.test/$(whoami)',
    'https://example.test/`whoami`',
    "https://example.test/'",
    'https://example.test/a&b',
    'https://example.test/%USERPROFILE%',
    'https://example.test/%20path%20',
  ])(
    'does not generate an unsafe or credential-bearing command: %s',
    address => {
      expect(
        assistantSetupCommand(address, 'https://app.example.test')
      ).toBeNull();
    }
  );
});
