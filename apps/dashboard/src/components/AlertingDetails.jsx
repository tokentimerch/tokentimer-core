import { useEffect, useId, useMemo, useRef, useState } from 'react';
import {
  Box,
  Collapse,
  Heading,
  HStack,
  Icon,
  Text,
  useColorModeValue,
} from '@chakra-ui/react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import { buildAlertLifecycleEventPath } from './AlertStateDisplay.jsx';
import { DASHBOARD_MODAL_HEADING_FONT } from './DashboardModalFrame.jsx';
import AlertStateDisplay, {
  AlertUpcomingSection,
} from './AlertStateDisplay.jsx';
import AlertLifecycleTimeline from './AlertLifecycleTimeline.jsx';

// Match CertificateDetailsModal "Job history" section chrome: heading +
// description, then a compact disclosure row for the content.
export default function AlertingDetails({
  token,
  enabled = true,
  ...boxProps
}) {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const focusEventId = useMemo(() => {
    const raw = searchParams.get('alert-event');
    if (!raw || !String(raw).startsWith('delivery:')) return null;
    const tokenIdParam = searchParams.get('token-id');
    if (
      tokenIdParam !== null &&
      token?.id !== null &&
      token?.id !== undefined &&
      String(tokenIdParam) !== String(token.id)
    ) {
      return null;
    }
    return raw;
  }, [searchParams, token?.id]);
  const [expanded, setExpanded] = useState(Boolean(focusEventId));
  const contentId = useId();
  const sectionRef = useRef(null);
  const rowHoverBg = useColorModeValue('gray.100', 'dashboard.table.rowHover');

  useEffect(() => {
    setExpanded(Boolean(focusEventId));
  }, [token?.id, focusEventId]);

  useEffect(() => {
    if (!focusEventId || !expanded) return undefined;
    const timer = window.setTimeout(() => {
      sectionRef.current?.scrollIntoView({
        block: 'start',
        behavior: 'smooth',
      });
    }, 120);
    return () => window.clearTimeout(timer);
  }, [focusEventId, expanded, token?.id]);

  const handleViewLatestAttempt = attemptId => {
    if (token?.id == null || attemptId == null) return;
    navigate(
      buildAlertLifecycleEventPath({
        tokenId: token.id,
        attemptId,
        workspaceId: token.workspace_id,
      })
    );
  };

  return (
    <Box
      ref={sectionRef}
      as='section'
      aria-label='Alerting and alert history'
      mb={6}
      minW={0}
      {...boxProps}
    >
      <Box mb={2}>
        <Heading
          as='h3'
          fontFamily={DASHBOARD_MODAL_HEADING_FONT}
          fontSize='sm'
          fontWeight='bold'
          letterSpacing='0.01em'
        >
          Alerting and alert history
        </Heading>
        <Text mt={1} fontSize='xs' color='dashboard.modal.muted'>
          See the current alert status, upcoming thresholds, and past delivery
          activity for this asset.
        </Text>
      </Box>
      <Box data-detail-row py={2}>
        <HStack
          as='button'
          type='button'
          w='full'
          textAlign='left'
          spacing={2}
          px={0}
          py={2}
          borderRadius='md'
          _hover={{ bg: rowHoverBg }}
          onClick={() => setExpanded(current => !current)}
          aria-label='Current status'
          aria-expanded={expanded}
          aria-controls={contentId}
        >
          <Icon
            as={expanded ? ChevronDown : ChevronRight}
            boxSize={3.5}
            color='dashboard.modal.muted'
            flexShrink={0}
          />
          <Text fontSize='sm' fontWeight='medium' flex='1' noOfLines={1}>
            Current status
          </Text>
        </HStack>
        <Collapse in={expanded} animateOpacity>
          <Box id={contentId} mt={1} ml={1} pl={3} py={2} borderLeftWidth='2px' borderColor='dashboard.modal.border'>
            <AlertStateDisplay
              alertState={token?.alert_state}
              tokenName={token?.name}
              tokenId={token?.id}
              workspaceId={token?.workspace_id}
              onViewLatestAttempt={handleViewLatestAttempt}
              showHeading={false}
              compact
            />
            <AlertUpcomingSection alertState={token?.alert_state} />
            <Box
              role='region'
              aria-label='History'
              borderTop='1px solid'
              borderColor='dashboard.modal.border'
              pt={4}
              mt={4}
            >
              <Text
                fontSize='xs'
                fontWeight='semibold'
                color='dashboard.modal.muted'
                mb={2}
              >
                History
              </Text>
              <AlertLifecycleTimeline
                tokenId={token?.id}
                alertState={token?.alert_state}
                enabled={enabled && expanded}
                compact
                showHeading={false}
                showUpcoming={false}
                focusEventId={focusEventId}
              />
            </Box>
          </Box>
        </Collapse>
      </Box>
    </Box>
  );
}
