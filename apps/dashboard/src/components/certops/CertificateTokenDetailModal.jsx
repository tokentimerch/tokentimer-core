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
import TokenDetailModal from '../TokenDetailModal.jsx';
import { TOKEN_CATEGORIES } from '../../constants/tokenCategories.js';
import apiClient, { tokenAPI, workspaceAPI } from '../../utils/apiClient';
import {
  DashboardModalFrame,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';

/**
 * Opens the same TokenDetailModal the main dashboard uses, for a
 * certificate's underlying token, from a page (CertOps certificates) that
 * only has a `tokenId` and never loaded the workspace's full token list.
 *
 * TokenDetailModal renders nothing at all while `token` is null (it bails
 * out before the Modal itself), so this wrapper shows its own loading shell
 * until the token, contact groups, and workspace contacts it needs have
 * been fetched, then hands off to the real modal.
 */
export default function CertificateTokenDetailModal({
  isOpen,
  onClose,
  workspaceId,
  tokenId,
  canManage,
}) {
  const { headerProps, bodyProps, closeButtonProps } = useDashboardModalProps();
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
      <TokenDetailModal
        token={token}
        isOpen={isOpen}
        onClose={onClose}
        TOKEN_CATEGORIES={TOKEN_CATEGORIES}
        isViewer={!canManage}
        contactGroups={contactGroups}
        workspaceContacts={workspaceContacts}
        onTokenUpdated={updated => setToken(updated)}
      />
    );
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered motionPreset='none'>
      <ModalOverlay />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '420px' }}>
        <ModalHeader {...headerProps}>Certificate details</ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps} pb={6}>
          <VStack spacing={3} py={4}>
            {loading ? (
              <>
                <Spinner size='md' />
                <Text fontSize='sm' color='gray.500'>
                  Loading token details...
                </Text>
              </>
            ) : (
              <Text fontSize='sm' color='red.500'>
                {error || 'This certificate has no linked token yet.'}
              </Text>
            )}
          </VStack>
        </ModalBody>
      </DashboardModalFrame>
    </Modal>
  );
}
