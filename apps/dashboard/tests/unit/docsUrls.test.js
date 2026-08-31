import { describe, it, expect } from 'vitest';
import { IMPORT_DOCS, SELF_HOSTED_DOCS_BASE } from '../../src/utils/docsUrls';

describe('IMPORT_DOCS', () => {
  it('points each import provider at the self-hosted docs page', () => {
    expect(SELF_HOSTED_DOCS_BASE).toBe(
      'https://tokentimer.ch/docs/self-hosted'
    );
    expect(IMPORT_DOCS.gcp).toBe(
      'https://tokentimer.ch/docs/self-hosted/integrations/gcp'
    );
    expect(IMPORT_DOCS.aws).toBe(
      'https://tokentimer.ch/docs/self-hosted/integrations/aws'
    );
    expect(IMPORT_DOCS.github).toBe(
      'https://tokentimer.ch/docs/self-hosted/integrations/github'
    );
    expect(IMPORT_DOCS.gitlab).toBe(
      'https://tokentimer.ch/docs/self-hosted/integrations/gitlab'
    );
    expect(IMPORT_DOCS.vault).toBe(
      'https://tokentimer.ch/docs/self-hosted/integrations/vault'
    );
    expect(IMPORT_DOCS.azureKeyVault).toBe(
      'https://tokentimer.ch/docs/self-hosted/integrations/azure-key-vault'
    );
    expect(IMPORT_DOCS.entraId).toBe(
      'https://tokentimer.ch/docs/self-hosted/integrations/entra-id'
    );
    expect(IMPORT_DOCS.file).toBe(
      'https://tokentimer.ch/docs/self-hosted/tokens/import-file'
    );
    expect(IMPORT_DOCS.integrations).toBe(
      'https://tokentimer.ch/docs/self-hosted/integrations'
    );
  });
});
