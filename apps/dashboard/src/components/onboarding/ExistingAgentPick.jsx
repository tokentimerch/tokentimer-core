import { Box, Checkbox, Select, Text, VStack } from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { formatRelativeDateTime } from '../certops/certopsJobsFormat.js';
import { agentMismatch, platformLabel, usesAgent } from './certopsMatrix.js';
import { StatusPanel } from './panels.jsx';

/** The workspace agents as the summary lists them, or null when unknown. */
export function workspaceAgents(ctx) {
  const certops = ctx.summary?.certops;
  const items = certops && certops !== 'unknown' ? certops.agents?.items : null;
  return Array.isArray(items) ? items : null;
}

/** The workspace agents that fit this pick, whether or not they are online. */
export function fittingAgents(ctx, objective, infra) {
  if (!usesAgent(infra)) return [];
  return (workspaceAgents(ctx) || []).filter(
    agent => !agentMismatch(agent, objective, infra)
  );
}

function agentName(agent) {
  return agent.hostname || agent.name || agent.id;
}

function optionLabel(agent, reason) {
  if (reason) return `${agentName(agent)} (${reason})`;
  const platform = platformLabel(agent.platform);
  const seen =
    agent.livenessState === 'live'
      ? 'live'
      : `offline, last seen ${formatRelativeDateTime(agent.lastSeenAt)}`;
  const version = agent.agentVersion ? `, v${agent.agentVersion}` : '';
  return `${agentName(agent)} (${platform}, ${seen}${version})`;
}

/**
 * "My agent is already set up": the explicit opt-in to reuse an agent of this
 * workspace for the chosen pick. Without it the guide installs a new agent.
 * Only agents that fit the pick can be selected; the others stay listed,
 * disabled, with the reason.
 */
export default function ExistingAgentPick({
  ctx,
  objective,
  infra,
  ticked,
  agentId,
  onTick,
  onAgent,
}) {
  const { muted } = useDashboardTheme();
  const items = workspaceAgents(ctx);
  // Kubernetes reports through a controller, and an API that does not list
  // agents cannot offer a choice: nothing to show then.
  if (!infra || !usesAgent(infra) || !items) return null;

  const rows = items.map(agent => ({
    agent,
    reason: agentMismatch(agent, objective, infra),
  }));
  const fitting = rows.filter(r => !r.reason);
  const picked = fitting.find(r => r.agent.id === agentId)?.agent;

  return (
    <VStack align='stretch' spacing={2} data-testid='existing-agent-pick'>
      <Checkbox
        isChecked={ticked && fitting.length > 0}
        isDisabled={fitting.length === 0}
        onChange={e => onTick(e.target.checked)}
      >
        <Text fontSize='sm' fontWeight='semibold'>
          My agent is already set up
        </Text>
      </Checkbox>
      {fitting.length === 0 ? (
        <Text fontSize='xs' color={muted} data-testid='no-fitting-agent'>
          No fitting agent found in this workspace yet.
        </Text>
      ) : null}
      {ticked && fitting.length > 0 ? (
        <Box pl={6}>
          <Select
            size='sm'
            aria-label='Choose your agent'
            placeholder='Choose an agent'
            value={picked ? agentId : ''}
            onChange={e => onAgent(e.target.value)}
          >
            {rows.map(({ agent, reason }) => (
              <option
                key={agent.id}
                value={agent.id}
                disabled={Boolean(reason)}
              >
                {optionLabel(agent, reason)}
              </option>
            ))}
          </Select>
          {picked && picked.livenessState !== 'live' ? (
            <Box mt={2}>
              <StatusPanel
                status='warning'
                title='This agent is not checking in'
                testId='agent-offline-warning'
              >
                <Text fontSize='sm'>
                  The guide waits for it to come online before the next step.
                </Text>
              </StatusPanel>
            </Box>
          ) : null}
        </Box>
      ) : null}
    </VStack>
  );
}
