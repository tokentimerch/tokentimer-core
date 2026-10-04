import CertOpsBadge from './CertOpsBadge.jsx';
import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Button,
  Checkbox,
  Flex,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Radio,
  RadioGroup,
  Stack,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';

const RETIRE_OPTIONS = [
  {
    value: 'decommissioned',
    label: 'Decommission',
    hint: 'Record that, to your knowledge, this certificate is no longer in use.',
  },
  {
    value: 'revoked',
    label: 'Mark revoked',
    hint: 'Record revocation in CertOps. This does not contact the certificate authority.',
  },
];

/**
 * Retire (soft lifecycle transition) for a managed certificate. Most callers
 * link a token (the token inventory's retire action, where the token cannot
 * be hard-deleted while it is backed by a managed certificate; see App.jsx),
 * but the Certificates tab operates on certificate rows directly and often
 * has no linked token at all (e.g. `agent_issuance` before reconciliation),
 * so `token` is optional and the certificate's own name/status carries the
 * subject line when it is absent. The certificate row and its evidence are
 * preserved and the status is mirrored onto the linked token, if any, by the
 * backend.
 */
export default function RetireCertificateModal({
  isOpen,
  onClose,
  token,
  certificate,
  onRetire,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    dangerButtonProps,
  } = useDashboardModalProps();

  const [status, setStatus] = useState('decommissioned');
  const [reason, setReason] = useState('');
  const [acknowledgeUncertainty, setAcknowledgeUncertainty] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen) {
      setStatus('decommissioned');
      setReason('');
      setAcknowledgeUncertainty(false);
      setSubmitting(false);
      setError('');
    }
  }, [isOpen]);

  const handleConfirm = async () => {
    if (submitting) return;
    if (!reason.trim()) {
      setError('Enter a reason for this lifecycle change.');
      return;
    }
    if (status === 'decommissioned' && !acknowledgeUncertainty) {
      setError('Confirm that you understand visibility may be incomplete.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await onRetire({ status, reason: reason.trim(), acknowledgeUncertainty });
    } catch (err) {
      const code = err?.response?.status;
      if (code === 404) {
        setError(
          'Retiring certificates is not available on this server yet. The backend retire endpoint is still being rolled out.'
        );
      } else {
        setError(
          err?.response?.data?.error ||
            'Could not retire this certificate. Please try again.'
        );
      }
      setSubmitting(false);
    }
  };

  const selected = RETIRE_OPTIONS.find(option => option.value === status);
  const subjectLabel =
    token?.name ||
    certificate?.commonName ||
    (Array.isArray(certificate?.subjectAltNames)
      ? certificate.subjectAltNames[0]
      : null) ||
    certificate?.id ||
    null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        type='danger'
        maxW={{ base: 'calc(100vw - 24px)', md: '520px' }}
      >
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Retire certificate</DashboardModalTitle>
          <DashboardModalDescription>
            This asset is backed by a managed certificate, so it cannot be
            deleted. Revoke or decommission it instead; the record and its
            history are kept.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          <VStack spacing={4} align='stretch'>
            {subjectLabel ? (
              <Text fontSize='sm'>
                <Text as='span' fontWeight='semibold'>
                  {subjectLabel}
                </Text>
                {certificate?.status ? (
                  <CertOpsBadge ml={2} colorScheme='gray'>
                    {certificate.status}
                  </CertOpsBadge>
                ) : null}
              </Text>
            ) : null}

            <RadioGroup value={status} onChange={setStatus}>
              <Stack spacing={3}>
                {RETIRE_OPTIONS.map(option => (
                  <Radio key={option.value} value={option.value}>
                    <Text fontSize='sm' fontWeight='medium'>
                      {option.label}
                    </Text>
                    <Text fontSize='xs' opacity={0.75}>
                      {option.hint}
                    </Text>
                  </Radio>
                ))}
              </Stack>
            </RadioGroup>

            <Alert status='warning' borderRadius='12px'>
              <AlertIcon />
              <AlertDescription fontSize='sm'>
                Renewal-failure alerts for this certificate will stop. Expiry
                alerts stop only when no other live certificate remains on this
                asset. Endpoint monitoring continues.
              </AlertDescription>
            </Alert>

            <Textarea
              value={reason}
              onChange={event => setReason(event.target.value)}
              placeholder='Reason (required, recorded in the audit trail)'
              size='sm'
              rows={2}
            />
            {status === 'decommissioned' ? (
              <Checkbox
                isChecked={acknowledgeUncertainty}
                onChange={event =>
                  setAcknowledgeUncertainty(event.target.checked)
                }
              >
                I understand CertOps may not see every location where this
                certificate is in use.
              </Checkbox>
            ) : null}

            {error ? (
              <Alert status='error' borderRadius='12px'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Flex
            w='100%'
            gap={3}
            justify={{ base: 'stretch', sm: 'flex-end' }}
            direction={{ base: 'column-reverse', sm: 'row' }}
          >
            <Button
              onClick={onClose}
              isDisabled={submitting}
              minW={{ base: '100%', sm: '104px' }}
              {...outlineButtonProps}
            >
              Cancel
            </Button>
            <Button
              onClick={handleConfirm}
              isLoading={submitting}
              minW={{ base: '100%', sm: '148px' }}
              {...dangerButtonProps}
            >
              {selected ? selected.label : 'Retire'}
            </Button>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
