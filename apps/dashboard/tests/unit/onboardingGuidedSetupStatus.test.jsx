import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { GoalStep } from '../../src/components/onboarding/steps.jsx';
import { ObjectiveStep } from '../../src/components/onboarding/certopsSetupSteps.jsx';
import { GOALS } from '../../src/components/onboarding/modules.js';
import { infrastructuresFor } from '../../src/components/onboarding/certopsMatrix.js';
import {
  CANDIDATE_EXPLANATION,
  CANDIDATE_NOTE,
  GUIDED_SETUP_STATUS,
  isCandidatePick,
  pickKey,
} from '../../src/components/onboarding/guidedSetupStatus.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const wrap = ui =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>{ui}</MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );

const makeCtx = goal => ({
  session: { intent: goal ? { goal } : {}, progress: {} },
  capabilities: null,
  plannerVersion: 2,
  docs: () => [],
  refresh: vi.fn().mockResolvedValue(undefined),
  onDone: vi.fn(),
  controller: { update: vi.fn().mockResolvedValue(undefined) },
});

const describedText = el =>
  (el.getAttribute('aria-describedby') || '')
    .split(' ')
    .map(id => document.getElementById(id)?.textContent)
    .join(' ');

// The shipped register changes as picks get verified, so render tests set
// their own: every key unverified, then the given keys verified.
function withRegister(verifiedKeys, run, { clearModuleFlags = false } = {}) {
  const saved = Object.entries(GUIDED_SETUP_STATUS).map(([k, v]) => [k, v]);
  const flags = Object.entries(GOALS).map(([k, g]) => [k, g.candidate]);
  for (const [k] of saved) {
    GUIDED_SETUP_STATUS[k] = {
      verified: verifiedKeys.includes(k),
      untested: verifiedKeys.includes(k) ? [] : ['x'],
      hint: saved.find(([key]) => key === k)[1].hint,
    };
  }
  if (clearModuleFlags) {
    for (const [k] of flags) delete GOALS[k].candidate;
  }
  try {
    run();
  } finally {
    saved.forEach(([k, v]) => {
      GUIDED_SETUP_STATUS[k] = v;
    });
    flags.forEach(([k, v]) => {
      if (v !== undefined) GOALS[k].candidate = v;
    });
  }
}
describe('guided setup register', () => {
  it('has an entry for every goal, so a new goal cannot skip it', () => {
    for (const id of Object.keys(GOALS)) {
      expect(GUIDED_SETUP_STATUS[id], `goal ${id}`).toBeTruthy();
    }
  });

  it('has an entry for every CertOps goal and infrastructure pick', () => {
    for (const [id, goal] of Object.entries(GOALS)) {
      if (!goal.certopsObjective) continue;
      for (const infra of infrastructuresFor(goal.certopsObjective)) {
        const key = pickKey(id, infra.id);
        expect(GUIDED_SETUP_STATUS[key], key).toBeTruthy();
      }
    }
  });

  it('lists what is untested for every unverified entry', () => {
    for (const [key, entry] of Object.entries(GUIDED_SETUP_STATUS)) {
      expect(typeof entry.verified, key).toBe('boolean');
      if (!entry.verified)
        expect(entry.untested.length, key).toBeGreaterThan(0);
    }
  });

  it('marks a pick when unverified or when the module flags it', () => {
    withRegister(['monitor_https'], () => {
      expect(isCandidatePick('import_file')).toBe(true);
      expect(isCandidatePick('not-in-register')).toBe(true);
      expect(isCandidatePick('monitor_https')).toBe(false);
      expect(isCandidatePick('monitor_https', true)).toBe(true);
    });
  });
  it('keeps the wording about the guided setup, not the feature', () => {
    expect(CANDIDATE_EXPLANATION).toMatch(/guided setup/);
    expect(CANDIDATE_EXPLANATION).toMatch(/feature itself may be fully/);
    expect(CANDIDATE_NOTE).toMatch(/Candidate/);
  });
});

describe('goal picker badges', () => {
  it('marks every unverified goal and shows the note once', () => {
    withRegister([], () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      const radios = screen.getAllByRole('radio');
      expect(radios).toHaveLength(Object.keys(GOALS).length);
      for (const radio of radios) {
        expect(describedText(radio)).toContain('Candidate');
        expect(describedText(radio)).toContain(CANDIDATE_NOTE);
      }
      expect(screen.getAllByText('Candidate')).toHaveLength(radios.length);
      expect(screen.getAllByText(CANDIDATE_NOTE)).toHaveLength(1);
    });
  });

  it('mixed register: only unverified goals carry the badge, the note stays', () => {
    withRegister(['monitor_https', 'track_asset'], () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      for (const name of [
        /Monitor a website certificate/,
        /Track an API key/,
      ]) {
        const text = describedText(screen.getByRole('radio', { name }));
        expect(text).not.toContain('Candidate');
        expect(text).not.toContain(CANDIDATE_NOTE);
      }
      const other = screen.getByRole('radio', { name: /Import many assets/ });
      expect(describedText(other)).toContain('Candidate');
      expect(screen.getAllByText('Candidate')).toHaveLength(
        Object.keys(GOALS).length - 2
      );
      expect(screen.getAllByText(CANDIDATE_NOTE)).toHaveLength(1);
    });
  });

  it('all-verified register: no badge and no note, nothing breaks', () => {
    withRegister(
      Object.keys(GUIDED_SETUP_STATUS),
      () => {
        wrap(<GoalStep ctx={makeCtx()} />);
        expect(screen.getAllByRole('radio')).toHaveLength(
          Object.keys(GOALS).length
        );
        expect(screen.queryByText('Candidate')).toBeNull();
        expect(screen.queryByText(CANDIDATE_NOTE)).toBeNull();
        expect(screen.queryByText(/qualified in 0.18.0/)).toBeNull();
      },
      { clearModuleFlags: true }
    );
  });

  it('a module candidate flag still marks a verified goal', () => {
    withRegister(Object.keys(GUIDED_SETUP_STATUS), () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      expect(screen.getAllByText('Candidate')).toHaveLength(1);
      expect(
        describedText(screen.getByRole('radio', { name: /Microsoft CA/ }))
      ).toContain('Candidate');
    });
  });

  it('separates the AD CS feature from its guided setup', () => {
    withRegister([], () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      const text = describedText(
        screen.getByRole('radio', {
          name: /Issue certificates from my Microsoft CA/,
        })
      );
      expect(text).toContain('AD CS enrollment is qualified in 0.18.0.');
      expect(text).toContain(
        'This guided setup has not been verified through a real enrollment yet.'
      );
    });
  });

  it('adds no per-row hint to picks without extra context', () => {
    withRegister([], () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      const radio = screen.getByRole('radio', {
        name: /Import many assets from a file/,
      });
      expect(describedText(radio)).not.toContain('qualified');
    });
  });
});

describe('shipped register', () => {
  it('clears only the picks with end-to-end evidence and keeps their caveats', () => {
    const verifiedKeys = Object.keys(GUIDED_SETUP_STATUS)
      .filter(k => GUIDED_SETUP_STATUS[k].verified)
      .sort();
    expect(verifiedKeys).toEqual(['monitor_https', 'track_asset']);
    for (const k of verifiedKeys) {
      expect(GUIDED_SETUP_STATUS[k].untested.length, k).toBeGreaterThan(0);
    }
  });

  it('shows a mixed picker: verified rows are clean, the note stays', () => {
    wrap(<GoalStep ctx={makeCtx()} />);
    for (const name of [
      /Monitor a website certificate/,
      /Track an API key, secret or license/,
    ]) {
      expect(describedText(screen.getByRole('radio', { name }))).not.toContain(
        'Candidate'
      );
    }
    for (const name of [
      /Set up alert notifications/,
      /Import many assets/,
      /Import from GitHub/,
      /Discover certificates/,
      /Issue and renew/,
      /Microsoft CA/,
      /Share one certificate/,
    ]) {
      expect(describedText(screen.getByRole('radio', { name }))).toContain(
        'Candidate'
      );
    }
    expect(screen.getAllByText('Candidate')).toHaveLength(7);
    expect(screen.getAllByText(CANDIDATE_NOTE)).toHaveLength(1);
  });

  it('marks Linux, Windows and Kubernetes observe', () => {
    wrap(<ObjectiveStep ctx={makeCtx('certops_observe')} />);
    const text = name => describedText(screen.getByRole('radio', { name }));
    expect(text(/Linux server/)).toContain('Candidate');
    expect(text(/Windows Server/)).toContain('Candidate');
    expect(text(/Kubernetes/)).toContain('Candidate');
    expect(screen.getAllByText('Candidate')).toHaveLength(3);
    expect(screen.getAllByText(CANDIDATE_NOTE)).toHaveLength(1);
  });
});

describe('note appears only above a list with a marked row', () => {
  it('a verified row carries no badge and no extra description', () => {
    withRegister(['monitor_https'], () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      const text = describedText(
        screen.getByRole('radio', { name: /Monitor a website certificate/ })
      );
      expect(text).toBe(
        'Track the HTTPS certificate of a site and get alerted before it expires.'
      );
    });
  });

  it('shows no note on a filtered list whose rows are all verified', () => {
    withRegister(
      ['monitor_https', 'track_asset', 'import_file', 'import_integration'],
      () => {
        render(
          <ChakraProvider>
            <DashboardThemeProvider>
              <MemoryRouter initialEntries={['/onboarding?area=assets']}>
                <GoalStep ctx={makeCtx()} />
              </MemoryRouter>
            </DashboardThemeProvider>
          </ChakraProvider>
        );
        expect(screen.getAllByRole('radio')).toHaveLength(4);
        expect(screen.queryByText(CANDIDATE_NOTE)).toBeNull();
        expect(screen.queryByText('Candidate')).toBeNull();
      }
    );
  });

  it('shows the note on a filtered list that has a marked row', () => {
    withRegister(['monitor_https', 'track_asset'], () => {
      render(
        <ChakraProvider>
          <DashboardThemeProvider>
            <MemoryRouter initialEntries={['/onboarding?area=assets']}>
              <GoalStep ctx={makeCtx()} />
            </MemoryRouter>
          </DashboardThemeProvider>
        </ChakraProvider>
      );
      expect(screen.getAllByText(CANDIDATE_NOTE)).toHaveLength(1);
      expect(screen.getAllByText('Candidate')).toHaveLength(2);
    });
  });
});
describe('infrastructure card badges', () => {
  it('marks every infrastructure card for every CertOps goal', () => {
    withRegister([], () => {
      for (const [id, goal] of Object.entries(GOALS)) {
        if (!goal.certopsObjective) continue;
        const view = wrap(<ObjectiveStep ctx={makeCtx(id)} />);
        const cards = screen.getAllByRole('radio');
        expect(cards).toHaveLength(
          infrastructuresFor(goal.certopsObjective).length
        );
        for (const card of cards) {
          expect(describedText(card), id).toContain('Candidate');
        }
        expect(screen.getAllByText(CANDIDATE_NOTE)).toHaveLength(1);
        view.unmount();
      }
    });
  });

  it('mixed register: a verified infrastructure pick has no badge', () => {
    withRegister(['certops_observe:linux'], () => {
      wrap(<ObjectiveStep ctx={makeCtx('certops_observe')} />);
      const linux = screen.getByRole('radio', { name: /Linux server/ });
      const windows = screen.getByRole('radio', { name: /Windows Server/ });
      expect(describedText(linux)).not.toContain('Candidate');
      expect(describedText(windows)).toContain('Candidate');
      expect(screen.getAllByText(CANDIDATE_NOTE)).toHaveLength(1);
    });
  });

  it('all-verified register: no badge and no note on the cards', () => {
    withRegister(Object.keys(GUIDED_SETUP_STATUS), () => {
      // Observe cards are qualified in the matrix, so only the register marks them.
      wrap(<ObjectiveStep ctx={makeCtx('certops_observe')} />);
      expect(screen.getAllByRole('radio')).toHaveLength(3);
      expect(screen.queryByText('Candidate')).toBeNull();
      expect(screen.queryByText(CANDIDATE_NOTE)).toBeNull();
    });
  });
  it('keeps the AD CS feature and guided setup apart on the Windows card', () => {
    withRegister([], () => {
      wrap(<ObjectiveStep ctx={makeCtx('certops_adcs')} />);
      const card = screen.getByRole('radio', { name: /Windows Server/ });
      const text = describedText(card);
      expect(text).toContain('AD CS enrollment is qualified in 0.18.0.');
      expect(text).toContain('not been verified through a real enrollment');
      expect(text).toContain('Server 2019 or later');
    });
  });
});
