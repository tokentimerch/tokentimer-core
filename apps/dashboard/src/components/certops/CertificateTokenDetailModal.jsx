import { useEffect, useState } from 'react';
import {
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalHeader,
  ModalOverlay,
  Spinner,
  Text,
  VStack,
} from '@chakra-ui/react';
import apiClient, { tokenAPI, workspaceAPI } from '../../utils/apiClient';
import {
  DashboardDetailsModalFrame,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import {
  DashboardDetailsModalFooter,
  DashboardDetailsModalHeader,
} from '../DashboardModalDetails.jsx';
import CertificateDetailsModal from './CertificateDetailsModal.jsx';
import { useCertOpsForToken } from './useCertOps.js';

function CertificateDetailsModalWithCertOps(props) {
  const certOps = useCertOpsForToken(props.token?.id);
  return (
    <CertificateDetailsModal
      {...props}
      certOps={certOps}
      compactTableSections
      propertyValueRows
    />
  );
}

/**
 * Loads the underlying token for the certificate selected on the CertOps
 * certificates page, which only has a `tokenId` and never loaded the
 * workspace's full token list.
 *
 * This wrapper shows a loading shell until the token, contact groups, and
 * workspace contacts are available, then mounts the certificate-specific
 * inspection modal and its managed-certificate enrichment.
 */
export default function CertificateTokenDetailModal({
  isOpen,
  onClose,
  workspaceId,
  tokenId,
  canManage,
}) {
  const {
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
    tokens: modalTokens,
  } = useDashboardModalProps();
  const [token, setToken] = useState(null);
  const [contactGroups, setContactGroups] = useState([]);
  const [workspaceContacts, setWorkspaceContacts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen || !tokenId) {
      setToken(null);
      setError('');
      return undefined;
    }
    let cancelled = false;
    setLoading(true);
    setError('');
    Promise.all([
      tokenAPI.getToken(tokenId),
      workspaceId
        ? workspaceAPI.getAlertSettings(workspaceId).catch(() => null)
        : Promise.resolve(null),
      workspaceId
        ? apiClient
            .get(`/api/v1/workspaces/${workspaceId}/contacts`)
            .catch(() => null)
        : Promise.resolve(null),
    ])
      .then(([tokenData, alertSettings, contactsRes]) => {
        if (cancelled) return;
        setToken(tokenData || null);
        setContactGroups(
          Array.isArray(alertSettings?.contact_groups)
            ? alertSettings.contact_groups
            : []
        );
        setWorkspaceContacts(
          Array.isArray(contactsRes?.data?.items) ? contactsRes.data.items : []
        );
      })
      .catch(err => {
        if (cancelled) return;
        setError(
          err?.message || 'Could not load this certificate\u2019s token.'
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isOpen, tokenId, workspaceId]);

  if (!isOpen) return null;

  if (token && !loading && !error) {
    return (
      <CertificateDetailsModalWithCertOps
        token={token}
        isOpen={isOpen}
        onClose={onClose}
        isViewer={!canManage}
        contactGroups={contactGroups}
        workspaceContacts={workspaceContacts}
        onTokenUpdated={updated => setToken(updated)}
      />
    );
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      scrollBehavior='inside'
      isCentered
      motionPreset='none'
    >
      <ModalOverlay />
      <DashboardDetailsModalFrame>
        <ModalHeader {...headerProps} py={{ base: 4, md: 4 }}>
          <DashboardDetailsModalHeader
            title='Certificate details'
            subtitle={
              loading
                ? 'Loading certificate data'
                : 'Certificate data unavailable'
            }
            badgeLabel='Certificate'
            badgeColorScheme='blue'
          />
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} top={{ base: 3, md: 3 }} />
        <ModalBody {...bodyProps} py={{ base: 4, md: 4 }}>
          <VStack align='start' spacing={3} py={2}>
            {loading ? (
              <>
                <Spinner size='sm' />
                <Text fontSize='sm' color={modalTokens.muted}>
                  Loading token details…
                </Text>
              </>
            ) : (
              <Text
                fontSize='sm'
                color={error ? modalTokens.danger : modalTokens.muted}
              >
                {error || 'This certificate has no linked token yet.'}
              </Text>
            )}
          </VStack>
        </ModalBody>
        <DashboardDetailsModalFooter
          footerProps={footerProps}
          tokens={modalTokens}
          isViewer
          isEditing={false}
          saveError=''
          saving={false}
          onClose={onClose}
          outlineButtonProps={outlineButtonProps}
          primaryButtonProps={primaryButtonProps}
          message={
            loading
              ? 'Loading asset details…'
              : 'Asset details are unavailable.'
          }
        />
      </DashboardDetailsModalFrame>
    </Modal>
  );
}
