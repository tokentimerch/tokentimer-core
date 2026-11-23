import { useState } from 'react';
import { Flex, Text, VStack } from '@chakra-ui/react';
import { FiCheck, FiCopy } from 'react-icons/fi';
import { DashboardActionButton } from './DashboardPrimitives';
import SsoWizardTestResults from './SsoWizardTestResults.jsx';
import { showWarning } from '../utils/toast.js';
import { useDashboardTheme } from '../hooks/useDashboardTheme';

// Plain text of the result for pasting into a ticket or a chat.
function resultAsText(result) {
  const lines = [];
  if (!result.ok && result.reason) lines.push(result.reason);
  for (const c of Array.isArray(result.checks) ? result.checks : []) {
    lines.push(
      `${c.ok ? 'PASS' : 'FAIL'} ${c.name}${c.detail ? `: ${c.detail}` : ''}`
    );
  }
  return lines.join('\n');
}

/**
 * Connectivity test result for the providers list: the same terminal style
 * check log as the setup wizard, plus a button to copy the lines.
 *
 * @param {{ result?: { ok?: boolean, reason?: string, checks?: Array<{ ok: boolean, name: string, detail?: string }> } | null, summary?: string }} props
 */
export default function SsoProviderTestResults({ result, summary }) {
  const { muted } = useDashboardTheme();
  const [copied, setCopied] = useState(false);
  if (!result) return null;

  const hasLines =
    (Array.isArray(result.checks) && result.checks.length > 0) ||
    (!result.ok && !!result.reason);

  async function copy() {
    try {
      await navigator.clipboard.writeText(resultAsText(result));
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
      showWarning('Copy failed');
    }
  }

  return (
    <VStack align='stretch' spacing={3}>
      {summary ? (
        <Text fontSize='sm' color={muted}>
          {summary}
        </Text>
      ) : null}
      <SsoWizardTestResults result={result} />
      {hasLines ? (
        <Flex justify='flex-end'>
          <DashboardActionButton
            size='xs'
            h='28px'
            variant='ghost'
            leftIcon={copied ? <FiCheck /> : <FiCopy />}
            onClick={copy}
          >
            {copied ? 'Copied' : 'Copy results'}
          </DashboardActionButton>
        </Flex>
      ) : null}
    </VStack>
  );
}
