import { useEffect, useState } from 'react';
import { VStack } from '@chakra-ui/react';
import { listAgents } from '../certops/certopsAgentsApi.js';
import { JobTimelineList } from './JobActivity.jsx';

/**
 * What the server knows about one agent: when it first registered, when it
 * last checked in, and what it runs on. The registration time is read from
 * the agents list because the setup summary does not carry it.
 */
export function agentEvents({ agent, registeredAt }) {
  if (!agent) return [];
  const events = [];
  if (registeredAt) {
    events.push({
      id: 'registered',
      at: registeredAt,
      label: 'Agent registered (first seen)',
      status: 'done',
    });
  }
  if (agent.lastSeenAt) {
    events.push({
      id: 'last-seen',
      at: agent.lastSeenAt,
      label: 'Last check-in',
      detail:
        agent.livenessState === 'live'
          ? 'The agent is reporting now.'
          : 'No recent check-in. The agent may be stopped or cannot reach this address.',
      status: agent.livenessState === 'live' ? 'done' : 'waiting',
    });
  }
  return events;
}

export default function AgentCheckIn({ workspaceId, agent }) {
  const [registeredAt, setRegisteredAt] = useState(null);
  const agentId = agent?.id;

  useEffect(() => {
    if (!workspaceId || !agentId) return undefined;
    const controller = new AbortController();
    listAgents(workspaceId, { signal: controller.signal })
      .then(res => {
        const found = (res.items || []).find(a => a.id === agentId);
        setRegisteredAt(found?.createdAt || null);
      })
      .catch(() => setRegisteredAt(null));
    return () => controller.abort();
  }, [workspaceId, agentId]);

  if (!agent) return null;
  return (
    <VStack align='stretch' spacing={3} data-testid='agent-checkin'>
      <JobTimelineList
        label='Agent timeline'
        events={agentEvents({ agent, registeredAt })}
      />
    </VStack>
  );
}
