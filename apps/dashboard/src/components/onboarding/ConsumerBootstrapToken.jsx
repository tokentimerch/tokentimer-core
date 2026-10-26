import { useState } from 'react';
import { Text, VStack } from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { createBootstrapToken } from '../certops/certopsAgentsApi.js';
import { CopyBlock } from './blocks.jsx';
import { StatusPanel } from './panels.jsx';

// Keep the one-time plaintext in this mounted view only, never guide progress.
export default function ConsumerBootstrapToken({ workspaceId }) {
  return <WorkspaceConsumerToken key={workspaceId} workspaceId={workspaceId} />;
}

function WorkspaceConsumerToken({ workspaceId }) {
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const create = async () => {
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      const result = await createBootstrapToken(workspaceId, {
        name: `Vault consumer ${new Date().toISOString()}`,
        expiresAt: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
      });
      if (typeof result.plaintextToken !== 'string' || !result.plaintextToken)
        throw new Error('No bootstrap token was returned.');
      setToken(result.plaintextToken);
    } catch (e) {
      setError(
        e?.response?.data?.error || e.message || 'Could not create a token.'
      );
    } finally {
      setBusy(false);
    }
  };
  return (
    <VStack align='stretch' spacing={3}>
      <Text fontSize='sm'>
        Each new consumer needs its own single-use bootstrap token. It expires
        in 24 hours. Paste it at the installer&apos;s hidden prompt; never add
        it to the command line. An already registered agent does not need
        another token.
      </Text>
      <DashboardActionButton
        variant='outline'
        onClick={create}
        isLoading={busy}
      >
        {token
          ? 'Create another consumer token'
          : 'Create a consumer bootstrap token'}
      </DashboardActionButton>
      {token ? (
        <CopyBlock
          label='One-time consumer bootstrap token'
          text={token}
          allowSecret
        />
      ) : null}
      {token ? (
        <Text fontSize='xs'>
          Save this token before leaving. Creating another token does not revoke
          an unused earlier one.
        </Text>
      ) : null}
      {error ? <StatusPanel status='error'>{error}</StatusPanel> : null}
    </VStack>
  );
}
