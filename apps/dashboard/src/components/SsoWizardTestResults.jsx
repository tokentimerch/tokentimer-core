import { Box, HStack, Text, VisuallyHidden, VStack } from '@chakra-ui/react';
import { FiCheck, FiX } from 'react-icons/fi';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { StatusPanel } from './onboarding/panels.jsx';
import { SHELL_BG, SHELL_BORDER, SHELL_TEXT } from './onboarding/blocks.jsx';

const SHELL_MUTED = '#94a3b8';
const SHELL_OK = '#4ade80';
const SHELL_FAIL = '#f87171';

/**
 * Connectivity test result for the SSO provider wizard, drawn as a terminal
 * style check log. It shows the reason and one line per check with its
 * detail. The providers list and the provider edit page reuse it through
 * SsoProviderTestResults, which adds a copy button.
 *
 * @param {{ result?: { ok?: boolean, reason?: string, checks?: Array<{ ok: boolean, name: string, detail?: string }> } | null }} props
 */
export default function SsoWizardTestResults({ result }) {
  const { muted } = useDashboardTheme();
  if (!result) return null;

  const checks = Array.isArray(result.checks) ? result.checks : [];

  return (
    <VStack align='stretch' spacing={3} aria-live='polite'>
      {!result.ok && result.reason ? (
        <StatusPanel status='warning' testId='sso-test-reason'>
          {result.reason}
        </StatusPanel>
      ) : null}
      {checks.length > 0 ? (
        <Box
          bg={SHELL_BG}
          borderWidth='1px'
          borderColor={SHELL_BORDER}
          borderRadius='md'
          p={3}
          overflowX='auto'
          tabIndex={0}
          role='region'
          aria-label='Connectivity checks'
          _focusVisible={{ boxShadow: 'outline', outline: 'none' }}
        >
          <VStack
            as='ul'
            align='stretch'
            spacing={2}
            listStyleType='none'
            m={0}
            p={0}
          >
            {checks.map((c, i) => (
              <HStack
                as='li'
                key={`${c.name}-${i}`}
                align='flex-start'
                spacing={3}
                fontFamily='mono'
                fontSize='xs'
                data-ok={c.ok ? 'true' : 'false'}
              >
                <Box
                  as='span'
                  aria-hidden
                  flexShrink={0}
                  mt='2px'
                  sx={{ color: `${c.ok ? SHELL_OK : SHELL_FAIL} !important` }}
                >
                  {c.ok ? <FiCheck /> : <FiX />}
                </Box>
                <Box minW={0} overflowWrap='anywhere'>
                  <Text
                    as='span'
                    fontWeight='semibold'
                    sx={{ color: `${SHELL_TEXT} !important` }}
                  >
                    <VisuallyHidden>
                      {c.ok ? 'Passed: ' : 'Failed: '}
                    </VisuallyHidden>
                    {c.name}
                  </Text>
                  {c.detail ? (
                    <Text
                      as='span'
                      display='block'
                      sx={{ color: `${SHELL_MUTED} !important` }}
                    >
                      {c.detail}
                    </Text>
                  ) : null}
                </Box>
              </HStack>
            ))}
          </VStack>
        </Box>
      ) : null}
      {checks.length === 0 && !result.reason ? (
        <Text fontSize='sm' color={muted}>
          No check details returned.
        </Text>
      ) : null}
    </VStack>
  );
}
