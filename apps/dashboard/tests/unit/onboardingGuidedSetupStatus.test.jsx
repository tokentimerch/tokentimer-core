import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { GoalStep } from '../../src/components/onboarding/steps.jsx';
import { ObjectiveStep } from '../../src/components/onboarding/certopsSetupSteps.jsx';
import { GOALS } from '../../src/components/onboarding/modules.js';
import { infrastructuresFor } from '../../src/components/onboarding/certopsMatrix.js';
import {
  CANDIDATE_BADGE,
  CANDIDATE_EXPLANATION,
  CANDIDATE_NOTE,
  CANDIDATE_REPORT_LABEL,
  CANDIDATE_REPORT_URL,
  GUIDED_SETUP_STATUS,
  entry,
  isCandidatePick,
  pickKey,
  untestedPlatformsNote,
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

  it('marks a pick from the register alone', () => {
    withRegister(['monitor_https'], () => {
      expect(isCandidatePick('import_file')).toBe(true);
      expect(isCandidatePick('not-in-register')).toBe(true);
      expect(isCandidatePick('monitor_https')).toBe(false);
      // A planning flag passed by mistake changes nothing.
      expect(isCandidatePick('monitor_https', true)).toBe(false);
    });
  });
  it('keeps the wording about the guided setup, not the feature', () => {
    expect(CANDIDATE_EXPLANATION).toMatch(/guided setup/);
    expect(CANDIDATE_EXPLANATION).toMatch(/feature itself may be fully/);
    expect(CANDIDATE_NOTE).toMatch(/Not fully tested/);
  });
});

describe('goal picker badges', () => {
  it('marks every unverified goal and shows the note once', () => {
    withRegister([], () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      const radios = screen.getAllByRole('radio');
      expect(radios).toHaveLength(Object.keys(GOALS).length);
      for (const radio of radios) {
        expect(describedText(radio)).toContain(CANDIDATE_BADGE);
        expect(describedText(radio)).toContain(CANDIDATE_NOTE);
      }
      expect(screen.getAllByText(CANDIDATE_BADGE)).toHaveLength(radios.length);
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
        expect(text).not.toContain(CANDIDATE_BADGE);
        expect(text).not.toContain(CANDIDATE_NOTE);
      }
      const other = screen.getByRole('radio', { name: /Import many assets/ });
      expect(describedText(other)).toContain(CANDIDATE_BADGE);
      expect(screen.getAllByText(CANDIDATE_BADGE)).toHaveLength(
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
        expect(screen.queryByText(CANDIDATE_BADGE)).toBeNull();
        expect(screen.queryByText(CANDIDATE_NOTE)).toBeNull();
        expect(screen.queryByText(/qualified in 0.18.0/)).toBeNull();
      },
      { clearModuleFlags: true }
    );
  });

  it('a module planning flag does not mark a verified goal', () => {
    expect(GOALS.certops_adcs.candidate).toBe(true);
    withRegister(Object.keys(GUIDED_SETUP_STATUS), () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      expect(screen.queryByText(CANDIDATE_BADGE)).toBeNull();
      expect(screen.queryByText(CANDIDATE_NOTE)).toBeNull();
    });
  });

  it('shows a register hint beside the badge of a pick that carries one', () => {
    withRegister([], () => {
      GUIDED_SETUP_STATUS.certops_adcs = entry(
        ['x'],
        'AD CS enrollment is qualified in 0.18.0. This guided setup has not been verified through a real enrollment yet.'
      );
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
  it('has every key verified and keeps each list of what was not covered', () => {
    for (const [key, item] of Object.entries(GUIDED_SETUP_STATUS)) {
      expect(item.verified, key).toBe(true);
      expect(item.untested.length, key).toBeGreaterThan(0);
      expect(item.hint, key).toBe('');
      expect(isCandidatePick(key), key).toBe(false);
    }
  });

  it('keeps a goal row consistent with its cards', () => {
    for (const [id, goal] of Object.entries(GOALS)) {
      if (!goal.certopsObjective) continue;
      const cards = infrastructuresFor(goal.certopsObjective).map(infra =>
        isCandidatePick(pickKey(id, infra.id))
      );
      expect(isCandidatePick(id), id).toBe(cards.some(Boolean));
      // A row lists what each of its cards left untested.
      for (const infra of infrastructuresFor(goal.certopsObjective)) {
        for (const line of GUIDED_SETUP_STATUS[pickKey(id, infra.id)]
          .untested) {
          expect(GUIDED_SETUP_STATUS[id].untested, `${id} ${line}`).toContain(
            line
          );
        }
      }
    }
  });

  it('shows a clean picker: no badge and no note', () => {
    wrap(<GoalStep ctx={makeCtx()} />);
    expect(screen.getAllByRole('radio')).toHaveLength(
      Object.keys(GOALS).length
    );
    expect(screen.queryByText(CANDIDATE_BADGE)).toBeNull();
    expect(screen.queryByText(CANDIDATE_NOTE)).toBeNull();
    expect(document.body.textContent).not.toMatch(
      /Not fully tested|not been verified|qualified in 0\.18\.0|Candidate/
    );
  });

  it('shows no badge on any infrastructure card of any CertOps goal', () => {
    for (const [id, goal] of Object.entries(GOALS)) {
      if (!goal.certopsObjective) continue;
      const view = wrap(<ObjectiveStep ctx={makeCtx(id)} />);
      expect(screen.getAllByRole('radio').length, id).toBeGreaterThan(0);
      expect(screen.queryByText(CANDIDATE_BADGE), id).toBeNull();
      expect(screen.queryByText(CANDIDATE_NOTE), id).toBeNull();
      expect(document.body.textContent, id).not.toMatch(
        /not been verified|qualified in 0\.18\.0/
      );
      view.unmount();
    }
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
        'Track the HTTPS certificate of a site and get alerted before it expires. About 2 min'
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
        expect(screen.queryByText(CANDIDATE_BADGE)).toBeNull();
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
      expect(screen.getAllByText(CANDIDATE_BADGE)).toHaveLength(2);
    });
  });
});
describe('Not fully tested wording', () => {
  it('links the shared note to the public issue tracker', () => {
    withRegister([], () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      const link = screen.getByRole('link', { name: CANDIDATE_REPORT_LABEL });
      expect(link.getAttribute('href')).toBe(CANDIDATE_REPORT_URL);
      expect(CANDIDATE_REPORT_URL).toBe(
        'https://github.com/tokentimerch/tokentimer-core/issues'
      );
    });
  });

  it('never says Candidate to the person', () => {
    withRegister([], () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      expect(document.body.textContent).not.toMatch(/Candidate/);
    });
  });

  it('names the untested platform on a goal row built from its cards', () => {
    withRegister(
      ['certops_observe:linux', 'certops_observe:kubernetes'],
      () => {
        wrap(<GoalStep ctx={makeCtx()} />);
        const row = screen.getByRole('radio', {
          name: /Discover certificates/,
        });
        expect(describedText(row)).toContain('Windows not fully tested');
      }
    );
  });

  it('adds no platform line when every card is marked', () => {
    withRegister([], () => {
      wrap(<GoalStep ctx={makeCtx()} />);
      const row = screen.getByRole('radio', { name: /Issue and renew/ });
      expect(describedText(row)).not.toMatch(/ not fully tested/);
    });
  });

  it('builds the platform note from the register only', () => {
    const cards = [
      { id: 'linux', label: 'Linux server', status: 'qualified' },
      { id: 'windows', label: 'Windows Server', status: 'qualified' },
    ];
    withRegister(['certops_automate:linux'], () => {
      expect(untestedPlatformsNote('certops_automate', cards)).toBe(
        'Windows not fully tested'
      );
    });
    withRegister([], () => {
      expect(untestedPlatformsNote('certops_automate', cards)).toBe('');
    });
    withRegister(['certops_automate:linux', 'certops_automate:windows'], () => {
      expect(untestedPlatformsNote('certops_automate', cards)).toBe('');
    });
  });
});

describe('time and requirement hints', () => {
  it('shows a rough time for every goal', () => {
    wrap(<GoalStep ctx={makeCtx()} />);
    for (const goal of Object.values(GOALS)) {
      expect(goal.time, goal.label).toBeTruthy();
    }
    expect(
      describedText(screen.getByRole('radio', { name: /Monitor a website/ }))
    ).toContain('About 2 min');
    expect(
      describedText(
        screen.getByRole('radio', { name: /Discover certificates/ })
      )
    ).toContain('Needs a server, about 20 min');
  });

  it('states what ACME and AD CS need up front', () => {
    wrap(<GoalStep ctx={makeCtx()} />);
    const acme = describedText(
      screen.getByRole('radio', { name: /Issue and renew/ })
    );
    expect(acme).toContain('Requires: a domain you control');
    expect(acme).toContain('DNS provider API token');
    const adcs = describedText(
      screen.getByRole('radio', { name: /Microsoft CA/ })
    );
    expect(adcs).toContain('Requires: a domain-joined Windows Server');
    expect(adcs).toContain('Enroll rights');
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
          expect(describedText(card), id).toContain(CANDIDATE_BADGE);
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
      expect(describedText(linux)).not.toContain(CANDIDATE_BADGE);
      expect(describedText(windows)).toContain(CANDIDATE_BADGE);
      expect(screen.getAllByText(CANDIDATE_NOTE)).toHaveLength(1);
    });
  });

  it('all-verified register: no badge and no note on the cards', () => {
    withRegister(Object.keys(GUIDED_SETUP_STATUS), () => {
      // Observe cards are qualified in the matrix, so only the register marks them.
      wrap(<ObjectiveStep ctx={makeCtx('certops_observe')} />);
      expect(screen.getAllByRole('radio')).toHaveLength(3);
      expect(screen.queryByText(CANDIDATE_BADGE)).toBeNull();
      expect(screen.queryByText(CANDIDATE_NOTE)).toBeNull();
    });
  });
  it('keeps the AD CS feature and guided setup apart on the Windows card', () => {
    withRegister([], () => {
      GUIDED_SETUP_STATUS['certops_adcs:windows'] = entry(
        ['x'],
        'AD CS enrollment is qualified in 0.18.0. This guided setup has not been verified through a real enrollment yet.'
      );
      wrap(<ObjectiveStep ctx={makeCtx('certops_adcs')} />);
      const card = screen.getByRole('radio', { name: /Windows Server/ });
      const text = describedText(card);
      expect(text).toContain('AD CS enrollment is qualified in 0.18.0.');
      expect(text).toContain('not been verified through a real enrollment');
      expect(text).toContain('Server 2019 or later');
    });
  });
});
