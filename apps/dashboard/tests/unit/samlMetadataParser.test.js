import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import {
  parseSamlMetadataXml,
  resolveSamlMetadataInput,
  POST_BINDING,
  REDIRECT_BINDING,
} from '../../src/lib/saml-metadata-parser.js';

const md = 'urn:oasis:names:tc:SAML:2.0:metadata';
const ds = 'http://www.w3.org/2000/09/xmldsig#';
const entityId = 'https://idp.example.test/metadata';
const endpoint = 'https://idp.example.test/sso';
const fixture = name =>
  new X509Certificate(
    readFileSync(
      resolve(
        dirname(fileURLToPath(import.meta.url)),
        '../../../../packages/agent/src/verify/fixtures',
        `${name}.crt.pem`
      )
    )
  );
const primary = fixture('leaf');
const rollover = fixture('material-renewed');
const encryption = fixture('intermediate');

const key = (cert, use) => `
  <md:KeyDescriptor${use ? ` use="${use}"` : ''}>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>
      ${cert.raw.toString('base64')}
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </md:KeyDescriptor>
`;
const service = (binding, path) =>
  `<md:SingleSignOnService Binding="${binding}" Location="${endpoint}/${path}" />`;
const entity = (keys, services) => `
  <md:EntityDescriptor xmlns:md="${md}" xmlns:ds="${ds}" entityID="${entityId}">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      ${keys}
      ${services}
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
`;

describe('SAML metadata XML parsing', () => {
  it('prefers Redirect over POST and retains two distinct signing certificates', () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <md:EntitiesDescriptor xmlns:md="${md}">
        <md:EntityDescriptor entityID="https://sp.example.test">
          <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
        </md:EntityDescriptor>
        ${entity(
          [
            key(encryption, 'encryption'),
            key(primary, 'signing'),
            key(primary),
            key(rollover),
          ].join(''),
          service(POST_BINDING, 'post') + service(REDIRECT_BINDING, 'redirect')
        )}
      </md:EntitiesDescriptor>`;
    const result = parseSamlMetadataXml(xml);
    expect(result).toEqual({
      ok: true,
      idpEntityId: entityId,
      entryPoint: endpoint + '/redirect',
      cert: primary.toString().trim(),
      secondaryCert: rollover.toString().trim(),
      authnRequestBinding: 'HTTP-Redirect',
      bindings: [POST_BINDING, REDIRECT_BINDING],
    });
  });

  it('uses POST when the IdP offers no Redirect service', () => {
    const xml = entity(key(primary), service(POST_BINDING, 'post'));
    expect(parseSamlMetadataXml(xml)).toMatchObject({
      ok: true,
      cert: primary.toString().trim(),
      entryPoint: endpoint + '/post',
      secondaryCert: '',
      authnRequestBinding: 'HTTP-POST',
      bindings: [POST_BINDING],
    });
  });

  it('ignores encryption-only and unrelated certificate uses', () => {
    const xml = entity(
      key(encryption, 'encryption') + key(primary, 'other'),
      service(REDIRECT_BINDING, 'redirect')
    );
    expect(parseSamlMetadataXml(xml)).toEqual({
      ok: false,
      error: 'No signing certificate found in metadata',
    });
  });

  it.each([
    [
      'malformed closing tags',
      '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><broken></md:EntityDescriptor>',
      /Invalid XML/,
    ],
    [
      'HTML',
      '<html><body><IDPSSODescriptor /></body></html>',
      /Unsupported SAML metadata/,
    ],
    [
      'wrong namespace',
      '<EntityDescriptor xmlns="urn:example:unrelated"><IDPSSODescriptor /></EntityDescriptor>',
      /Unsupported SAML metadata/,
    ],
    [
      'SP-only metadata',
      `<EntityDescriptor xmlns="${md}"><SPSSODescriptor /></EntityDescriptor>`,
      /No IDPSSODescriptor/,
    ],
    [
      'document type declarations',
      '<!DOCTYPE EntityDescriptor><EntityDescriptor />',
      /document type declaration/,
    ],
  ])('rejects %s', (_label, xml, error) => {
    expect(parseSamlMetadataXml(xml)).toEqual({
      ok: false,
      error: expect.stringMatching(error),
    });
  });

  it('uses the same data-only parser for proxied metadata URLs', async () => {
    const fetchMetadataUrl = vi
      .fn()
      .mockResolvedValue(
        entity(key(primary), service(REDIRECT_BINDING, 'redirect'))
      );
    await expect(
      resolveSamlMetadataInput({
        metadataUrl: entityId,
        fetchMetadataUrl,
      })
    ).resolves.toMatchObject({ ok: true, cert: primary.toString().trim() });
    expect(fetchMetadataUrl).toHaveBeenCalledExactlyOnceWith(entityId);
  });
});
