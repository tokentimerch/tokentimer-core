import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it } from 'vitest';
import JobApprovalScope from '../../src/components/certops/JobApprovalScope.jsx';

describe('original-deployment reconciliation approval scope', () => {
  it('shows original scope and read-only boundary without exposing arbitrary payload fields', () => {
    render(
      <ChakraProvider>
        <JobApprovalScope
          job={{
            operation: 'reconcile-from-store',
            payload: {
              materialReconciliation: {
                originalJobId: 'old-job',
                assignedAgentId: 'same-agent',
                workspaceAuthorizationRevision: '9',
                intent: {
                  groupId: 'group',
                  bindingId: 'binding',
                  materialVersionId: 'pinned-version',
                  generation: 7,
                  fingerprintSha256: 'fingerprint',
                  deploymentProfileRef: 'web-local',
                  verificationPolicy: 'installed',
                  preparationOnly: true,
                  unsafeExtra: 'do-not-render',
                },
                privateExtra: 'secret-do-not-render',
              },
            },
          }}
        />
      </ChakraProvider>
    );
    for (const value of [
      'old-job',
      'same-agent',
      'pinned-version',
      'fingerprint',
      'web-local',
      'installed',
    ])
      expect(screen.getByText(value)).toBeInTheDocument();
    expect(screen.getByText('Preparation only')).toBeInTheDocument();
    expect(
      screen.getByText(/Do not install material, reload services/)
    ).toBeInTheDocument();
    expect(screen.queryByText('do-not-render')).not.toBeInTheDocument();
    expect(screen.queryByText('secret-do-not-render')).not.toBeInTheDocument();
  });
});
