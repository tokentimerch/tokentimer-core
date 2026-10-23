import { describe, expect, it } from 'vitest';
import {
  adcsIssuerLink,
  adcsRecheckLink,
  parseAdcsIssuerRequest,
  parseAdcsRecheckRequest,
  withoutAdcsIssuerRequest,
} from '../../src/components/certops/adcsIssuerLink.js';

const AGENT = '3f2b9c1e-5d4a-4b7e-8c21-0a9d8e7f6b5c';

describe('adcsIssuerLink', () => {
  it('builds the documented deep link', () => {
    expect(adcsIssuerLink({ workspaceId: 'ws-1' })).toBe(
      '/certops/renewals?workspace=ws-1&action=new-adcs-issuer'
    );
  });

  it('adds only the optional values that are set', () => {
    const link = adcsIssuerLink({
      workspaceId: 'ws-1',
      agentId: AGENT,
      caConfig: 'ca01.corp.example.com\\Corp CA',
      template: 'WebServer',
    });
    const params = new URL(link, 'http://x').searchParams;
    expect(params.get('agentId')).toBe(AGENT);
    expect(params.get('caConfig')).toBe('ca01.corp.example.com\\Corp CA');
    expect(params.get('template')).toBe('WebServer');
  });
});

describe('parseAdcsIssuerRequest', () => {
  const parse = query => parseAdcsIssuerRequest(new URLSearchParams(query));

  it('ignores a URL without the action', () => {
    expect(parse('workspace=ws-1')).toBeNull();
    expect(parse('action=something-else')).toBeNull();
  });

  it('reads the prefill and drops values the form cannot use', () => {
    expect(
      parse(`action=new-adcs-issuer&agentId=${AGENT}&template=WebServer`)
    ).toEqual({ agentId: AGENT, caConfig: '', template: 'WebServer' });
    expect(parse('action=new-adcs-issuer&agentId=not-an-id')).toEqual({
      agentId: '',
      caConfig: '',
      template: '',
    });
    expect(
      parse(`action=new-adcs-issuer&template=${'x'.repeat(65)}`).template
    ).toBe('');
  });

  it('removes the request but keeps the workspace', () => {
    const next = withoutAdcsIssuerRequest(
      new URLSearchParams(
        `workspace=ws-1&action=new-adcs-issuer&agentId=${AGENT}&profileOffset=20`
      )
    );
    expect(next.toString()).toBe('workspace=ws-1&profileOffset=20');
  });
});

describe('adcsRecheckLink', () => {
  it('builds a link that names the issuer', () => {
    expect(adcsRecheckLink({ workspaceId: 'ws-1', issuerId: AGENT })).toBe(
      `/certops/renewals?workspace=ws-1&action=check-adcs-issuer&issuerId=${AGENT}`
    );
  });

  it('reads the issuer back and drops a malformed id', () => {
    const url = new URL(
      adcsRecheckLink({ workspaceId: 'ws-1', issuerId: AGENT }),
      'http://x'
    );
    expect(parseAdcsRecheckRequest(url.searchParams)).toEqual({
      issuerId: AGENT,
    });
    expect(
      parseAdcsRecheckRequest(
        new URLSearchParams('action=check-adcs-issuer&issuerId=nope')
      )
    ).toBeNull();
    expect(
      parseAdcsRecheckRequest(new URLSearchParams(`issuerId=${AGENT}`))
    ).toBeNull();
  });

  it('is removed with the other issuer request parameters', () => {
    const next = withoutAdcsIssuerRequest(
      new URLSearchParams(
        `workspace=ws-1&action=check-adcs-issuer&issuerId=${AGENT}`
      )
    );
    expect(next.toString()).toBe('workspace=ws-1');
  });
});
