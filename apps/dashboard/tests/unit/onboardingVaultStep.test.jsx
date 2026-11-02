import {
  act,
  fireEvent,
  render,
  screen,
  within,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { VaultStep } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import {
  buildApiCall,
  buildApiRead,
  buildApiSignIn,
  buildVaultConfigs,
} from '../../src/components/onboarding/certopsConfig.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { createJob } from '../../src/components/certops/certopsJobsApi.js';

vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  createJob: vi.fn(),
  getJob: vi.fn(),
}));
vi.mock('../../src/components/onboarding/vaultGuideApi.js', () => ({
  readDistribution: vi.fn().mockResolvedValue({ versions: [], consumers: [] }),
  assignConsumer: vi.fn(),
  requestRollout: vi.fn(),
  retryDeployment: vi.fn(),
}));

const policy = vi.hoisted(() => ({ required: null }));
vi.mock(
  '../../src/components/onboarding/approvalPolicy.jsx',
  async original => ({
    ...(await original()),
    useJobApprovalPolicy: () => ({ required: policy.required }),
  })
);
beforeEach(() => {
  policy.required = null;
  vi.clearAllMocks();
});

const WS = '11111111-1111-4111-8111-111111111111';
const GROUP = '22222222-2222-4222-8222-222222222222';

function ctxWith(certops = {}) {
  const session = {
    progress: {
      certops: {
        objective: 'vault',
        names: 'a.example.com',
        zone: 'example.com',
        ...certops,
      },
    },
  };
  return {
    docs: () => [],
    workspaceId: WS,
    apiUrl: 'https://tt.example.com',
    refresh: vi.fn().mockResolvedValue(undefined),
    session,
    controller: {
      update: vi.fn(mutate => {
        Object.assign(session, mutate(session));
        return Promise.resolve();
      }),
    },
    summary: {
      certops: {
        agents: {
          items: [
            {
              id: 'i1',
              wireAgentId: 'issuer-1',
              platform: 'linux',
              commandProfiles: ['certbot'],
            },
            {
              id: 'c1',
              wireAgentId: 'consumer-1',
              platform: 'linux',
              commandProfiles: [],
            },
          ],
        },
        distribution: { groups: 0, bindings: 0 },
      },
    },
  };
}

const show = ctx =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <VaultStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

const ready = {
  vaultAddress: 'https://vault.example.com:8200',
  groupId: GROUP,
};

describe('Vault step structure', () => {
  it('keeps polling the selected distribution while another distribution is already complete', async () => {
    vi.useFakeTimers();
    const ctx = ctxWith(ready);
    ctx.summary.certops.distribution = {
      groups: 2,
      completed: true,
      verified: true,
      items: [
        { id: 'another-group', completed: true, verified: true },
        { id: GROUP, completed: false, verified: false },
      ],
    };
    let view;
    try {
      view = show(ctx);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(15000);
      });
      expect(ctx.refresh).toHaveBeenCalled();
      expect(screen.getByText('Setup in progress')).toBeInTheDocument();
      expect(
        screen.queryByText('Distribution verified')
      ).not.toBeInTheDocument();
    } finally {
      view?.unmount();
      vi.useRealTimers();
    }
  });

  it('recovers a lost publication response with the saved key, but a fresh setup has a new key', async () => {
    const ctx = ctxWith(ready);
    createJob.mockRejectedValueOnce(new Error('Response lost'));
    let view = show(ctx);
    const submit = () => {
      fireEvent.click(
        screen.getByRole('checkbox', {
          name: 'The issuing TokenTimer agent is stopped while I prepare Vault',
        })
      );
      fireEvent.click(
        screen.getByRole('button', { name: 'Create the publish job' })
      );
    };
    submit();
    await screen.findByText('Response lost');
    const firstKey = createJob.mock.calls[0][1].idempotencyKey;
    expect(ctx.session.progress.certops.vaultPublishRequestKey).toBe(firstKey);
    view.unmount();
    createJob.mockResolvedValue({
      job: {
        id: 'publication',
        status: 'pending',
        payload: { publication: { groupId: GROUP } },
      },
    });
    view = show(ctx);
    submit();
    await waitFor(() => expect(createJob).toHaveBeenCalledTimes(2));
    expect(createJob.mock.calls[1][1].idempotencyKey).toBe(firstKey);
    view.unmount();
    view = show(ctxWith(ready));
    submit();
    await waitFor(() => expect(createJob).toHaveBeenCalledTimes(3));
    expect(createJob.mock.calls[2][1].idempotencyKey).not.toBe(firstKey);
    view.unmount();
  });
  it.each([true, false])(
    'explains the loaded rollout approval policy (%s) without an unconditional second-user requirement',
    required => {
      policy.required = required;
      show(ctxWith(ready));
      const part = screen.getByTestId('vault-part-6');
      expect(
        within(part).getByTestId(
          required ? 'approval-policy-on' : 'approval-policy-off'
        )
      ).toBeInTheDocument();
      expect(part.textContent).not.toMatch(
        /always needs approval|whatever the workspace/
      );
      if (!required) {
        expect(screen.getByTestId('vault-part-1').textContent).toMatch(
          /Stop only the issuing TokenTimer agent service/
        );
        expect(part.textContent).toMatch(
          /Approval is off for this workspace, jobs start right away/
        );
      } else {
        expect(part.textContent).toMatch(
          /workspace manager other than the person who creates it/
        );
      }
    }
  );

  it('splits the work into numbered parts that say who does what', () => {
    show(ctxWith(ready));
    const parts = [1, 2, 3, 4, 5, 6].map(n =>
      screen.getByTestId(`vault-part-${n}`)
    );
    expect(parts[0].textContent).toMatch(
      /1\. Check your agents and prepare publication/
    );
    expect(parts[0].textContent).toMatch(/You, in this dashboard/);
    expect(parts[2].textContent).toMatch(/Vault administrator/);
    expect(parts[3].textContent).toMatch(/issuing server/);
    expect(parts[4].textContent).toMatch(/consumer server/);
    expect(parts[5].textContent).toMatch(
      /You, in this dashboard \(workspace manager\)/
    );
    expect(
      within(parts[5]).getByRole('button', {
        name: 'Deploy the selected version',
      })
    ).toBeDisabled();
    expect(parts[5].textContent).not.toMatch(
      /always needs approval|whatever the workspace/
    );
  });

  it('has one primary Save action and says why it is off', () => {
    show(ctxWith());
    const save = screen.getByRole('button', { name: 'Save these settings' });
    expect(save).toBeDisabled();
    expect(screen.getByTestId('vault-save-hint').textContent).toMatch(
      /the Vault address, the group id/
    );
    expect(screen.queryByTestId('vault-part-3')).toBeNull();
  });

  it('saves Vault connection details beside the fields', async () => {
    const ctx = ctxWith(ready);
    show(ctx);
    fireEvent.click(
      screen.getByRole('button', { name: 'Save Vault connection settings' })
    );
    expect(
      await screen.findByText('Vault connection settings saved.')
    ).toBeInTheDocument();
    expect(ctx.session.progress.certops.vaultAddress).toBe(ready.vaultAddress);
    expect(screen.getByText('Setup in progress')).toBeInTheDocument();
  });

  it('saves and confirms once the values are valid', async () => {
    const ctx = ctxWith(ready);
    show(ctx);
    fireEvent.click(
      screen.getByRole('button', { name: 'Save these settings' })
    );
    expect(await screen.findByTestId('vault-saved')).toBeInTheDocument();
    expect(ctx.session.progress.certops.configReviewed).toBe(true);
  });

  it('shows a field error only after the field was left', () => {
    show(ctxWith());
    expect(screen.queryByText(/must use https/)).toBeNull();
    fireEvent.blur(screen.getByLabelText('Vault address'));
    expect(
      screen.getByText('The Vault address must use https.')
    ).toBeInTheDocument();
  });

  it('keeps the jargon error names inside the collapsed panel', () => {
    show(ctxWith(ready));
    const panel = screen.getByTestId('vault-uncertain-note');
    expect(panel.tagName).toBe('DETAILS');
    expect(panel.hasAttribute('open')).toBe(false);
    const outside = document.body.textContent.replace(panel.textContent, '');
    expect(outside).not.toMatch(
      /orphaned_unknown_effect|material_binding_uncertain/
    );
    expect(panel.textContent).toMatch(/reconcile-material-binding\.js/);
  });

  it('keeps every proven command', () => {
    show(
      ctxWith({
        ...ready,
        vaultConsumerDeliveryMode: 'service',
        vaultConsumerDeployPath: '/etc/nginx/tokentimer',
      })
    );
    const text = document.body.textContent;
    expect(text).toMatch(/--write-path '\/etc\/nginx\/tokentimer'/);
    expect(text).toMatch(/sudo -u tokentimer-agent openssl req/);
    expect(text).toMatch(/vault policy write tt-issuer issuer\.hcl/);
    expect(text).toMatch(/systemctl daemon-reload/);
    expect(text).toMatch(/Send a test job/);
  });
});

describe('Vault API examples', () => {
  it('signs in with prompts, never with a secret in the command', () => {
    const text = buildApiSignIn({
      apiUrl: 'https://tt.example.com/',
      workspaceId: WS,
    });
    expect(text).toContain("API='https://tt.example.com'");
    expect(text).toContain(`WS='${WS}'`);
    expect(text).toMatch(/read -r -s -p 'TokenTimer password: '/);
    expect(text).toMatch(/X-CSRF-Token/);
    expect(text).toContain('/auth/login');
    expect(text).not.toMatch(/\u2014|ttx_|ttboot_/);
  });

  it('builds a curl with the session, the CSRF header and the body', () => {
    const text = buildApiCall({
      method: 'POST',
      path: 'certops/jobs',
      body: { a: 1 },
      idempotencyKey: 'k1',
    });
    expect(text).toContain('-X POST "$API/api/v1/workspaces/$WS/certops/jobs"');
    expect(text).toContain("-H 'Idempotency-Key: k1'");
    expect(text).toContain('"a": 1');
    expect(buildApiRead('x/y')).toContain('"$API/api/v1/workspaces/$WS/x/y"');
  });

  it('offers inline assignment and version selection instead of API command placeholders', () => {
    show(ctxWith(ready));
    const text = document.body.textContent;
    expect(
      screen.getByRole('button', { name: 'Assign consumer-1' })
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText('Published certificate version')
    ).toBeInTheDocument();
    expect(text).not.toContain('VERSION_ID_FROM_GROUP_VERSIONS');
    expect(text).not.toContain('Sign in for the API calls');
  });
});

describe('Vault config errors by field', () => {
  it('groups problems by the field they belong to', () => {
    const res = buildVaultConfigs({
      vaultAddress: 'http://v',
      workspaceId: WS,
      groupId: 'x',
      names: [],
      zone: 'example.com',
    });
    expect(res.ok).toBe(false);
    expect(Object.keys(res.fieldErrors).sort()).toEqual([
      'groupId',
      'names',
      'vaultAddress',
    ]);
  });
});
