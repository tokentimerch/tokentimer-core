import {
  memo,
  startTransition,
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Button,
  Checkbox,
  Collapse,
  Divider,
  FormControl,
  FormLabel,
  HStack,
  IconButton,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  NumberInput,
  NumberInputField,
  Select,
  Stack,
  Switch,
  Table,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tooltip,
  Tr,
  VStack,
  useBreakpointValue,
} from '@chakra-ui/react';
import {
  FiAlertTriangle,
  FiChevronDown,
  FiChevronUp,
  FiExternalLink,
  FiPlus,
  FiRefreshCw,
  FiTrash2,
} from 'react-icons/fi';
import toast from 'react-hot-toast';
import apiClient, { showSuccessMessage } from '../utils/apiClient';
import { logger } from '../utils/logger.js';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import {
  domainFormatUrl,
  domainSslBadge,
  domainStatusColor,
} from '../utils/domains.jsx';
import {
  DashboardModalFrame,
  useDashboardModalProps,
} from './DashboardModalFrame.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme.js';

const DOMAIN_CHECKER_PAGE_SIZE = 50;
const ENDPOINT_MONITORS_PAGE_SIZE = 40;
const DOMAIN_CHECKER_LOOKUP_TIMEOUT_MS = 300_000;
const DOMAIN_CHECKER_IMPORT_CHUNK_SIZE = 25;
const DOMAIN_CHECKER_IMPORT_CHUNK_TIMEOUT_MS = 300_000;

function normalizeDomainCheckerStringArray(value) {
  if (Array.isArray(value)) {
    return value.map(item => String(item || '').trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    return value
      .split(',')
      .map(item => item.trim())
      .filter(Boolean);
  }
  return [];
}

function normalizeDomainCheckerItems(value) {
  const rawItems = Array.isArray(value) ? value : [];
  const seen = new Set();
  return rawItems
    .map((item, index) => {
      const record = item && typeof item === 'object' ? item : { name: item };
      const domains = normalizeDomainCheckerStringArray(
        record.domains || record.domain || record.hostname || record.name
      );
      const name = String(
        record.name || record.hostname || record.commonName || domains[0] || ''
      ).trim();
      if (!name) return null;
      const id = String(record.id || `disc-${name}-${index}`);
      const key = id || name;
      if (seen.has(key)) return null;
      seen.add(key);
      return {
        ...record,
        id,
        name,
        domains: domains.length ? domains : [name],
        sources: normalizeDomainCheckerStringArray(
          record.sources || record.source
        ),
        checked: record.checked !== false,
      };
    })
    .filter(Boolean);
}

function normalizeDomainCheckerToolErrors(value) {
  return (Array.isArray(value) ? value : [])
    .map(error => {
      if (typeof error === 'string') return { tool: error };
      if (!error || typeof error !== 'object') return null;
      return {
        tool: String(error.tool || error.code || '').trim(),
        message: String(error.message || '').trim(),
      };
    })
    .filter(error => error && (error.tool || error.message));
}

const DomainCheckerRow = memo(function DomainCheckerRow({
  cert,
  isSelected,
  onToggle,
}) {
  const domains = Array.isArray(cert.domains) ? cert.domains : [];
  return (
    <Tr>
      <Td>
        <Checkbox isChecked={isSelected} onChange={() => onToggle(cert.id)} />
      </Td>
      <Td>
        <Text fontSize='sm' fontWeight='medium'>
          {cert.name}
        </Text>
      </Td>
      <Td fontSize='xs'>
        {domains.slice(0, 6).join(', ')}
        {domains.length > 6 ? ` +${domains.length - 6} more` : ''}
      </Td>
    </Tr>
  );
});

const EndpointSslMonitorModal = memo(function EndpointSslMonitorModal({
  isOpen,
  onClose,
  contactGroups,
  defaultContactGroupId = '',
  panelQueries,
  TOKEN_CATEGORIES,
  fetchGlobalFacets,
  fetchTokensForCategoryReset,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    fieldProps,
    tokens: modalTokens,
  } = useDashboardModalProps();
  const { muted, border, dashboard } = useDashboardTheme();
  const mobileCardBg = dashboard.bg.panelHover;

  const { workspaceId: ctxWorkspaceId } = useWorkspace();

  // Endpoint form state
  const [domainUrl, setDomainUrl] = useState('');
  const [domainHealthCheck, setDomainHealthCheck] = useState(true);
  const [domainInterval, setDomainInterval] = useState('hourly');
  const [domainAlertAfter, setDomainAlertAfter] = useState(2);
  const [domainContactGroupId, setDomainContactGroupId] = useState(
    defaultContactGroupId || ''
  );
  const [addingDomain, setAddingDomain] = useState(false);
  const [domains, setDomains] = useState([]);
  const [domainsLoading, setDomainsLoading] = useState(false);
  const [checkingDomain, setCheckingDomain] = useState(null);
  const [domainListSort, setDomainListSort] = useState({
    key: 'az',
    direction: 'asc',
  });
  const [endpointMonitorsPage, setEndpointMonitorsPage] = useState(0);
  const [domainEndpointTokenSection, setDomainEndpointTokenSection] =
    useState('');

  // Domain checker state
  const [domainCheckerInput, setDomainCheckerInput] = useState('');
  const [domainCheckerResults, setDomainCheckerResults] = useState([]);
  const [selectedIds, setSelectedIds] = useState(() => new Set());
  const [domainCheckerLoading, setDomainCheckerLoading] = useState(false);
  const [domainCheckerImporting, setDomainCheckerImporting] = useState(false);
  const [domainCheckerPartial, setDomainCheckerPartial] = useState(false);
  const [domainCheckerTruncated, setDomainCheckerTruncated] = useState(false);
  const [domainCheckerCapCount, setDomainCheckerCapCount] = useState(500);
  const [domainCheckerToolErrors, setDomainCheckerToolErrors] = useState([]);
  const [domainCheckerCreateMonitors, setDomainCheckerCreateMonitors] =
    useState(false);
  const [domainCheckerMonitorHealthCheck, setDomainCheckerMonitorHealthCheck] =
    useState(false);
  const [domainCheckerMonitorInterval, setDomainCheckerMonitorInterval] =
    useState('hourly');
  const [domainCheckerMonitorAlertAfter, setDomainCheckerMonitorAlertAfter] =
    useState(2);
  const [
    domainCheckerMonitorContactGroupId,
    setDomainCheckerMonitorContactGroupId,
  ] = useState(defaultContactGroupId || '');
  const [domainCheckerImportSection, setDomainCheckerImportSection] =
    useState('');
  const domainCheckerImportInFlightRef = useRef(false);
  const [domainCheckerPage, setDomainCheckerPage] = useState(0);
  const [domainCheckerSubfinderAll, setDomainCheckerSubfinderAll] =
    useState(false);
  const [domainCheckerImportReport, setDomainCheckerImportReport] =
    useState(null);
  const [domainCheckerImportReportOpen, setDomainCheckerImportReportOpen] =
    useState(false);

  const handleDomainModalClose = () => {
    setDomainCheckerImportReport(null);
    setDomainCheckerImportReportOpen(false);
    onClose();
  };

  const loadDomains = useCallback(async () => {
    if (!ctxWorkspaceId) return;
    setDomainsLoading(true);
    const maxAttempts = 3;
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      try {
        const res = await apiClient.get(
          `/api/v1/workspaces/${ctxWorkspaceId}/domains`
        );
        setDomains(res.data?.items || []);
        setDomainsLoading(false);
        return;
      } catch (e) {
        const status = e?.response?.status;
        const isTransient = !status || status >= 500 || status === 429;
        if (attempt < maxAttempts - 1 && isTransient) {
          await new Promise(r => setTimeout(r, 1500 * (attempt + 1)));
          continue;
        }
        logger.error('Failed to load endpoint monitors', e);
      }
    }
    setDomainsLoading(false);
  }, [ctxWorkspaceId]);

  const visibleDomains = useMemo(() => {
    const healthOf = item => String(item?.last_health_status || 'pending');
    const intervalOrder = {
      '1min': 0,
      '5min': 1,
      '15min': 2,
      hourly: 3,
      daily: 4,
    };
    const healthOrder = {
      healthy: 0,
      warning: 1,
      error: 2,
      pending: 3,
    };
    const expirationTs = item => {
      const raw = item?.ssl_valid_to || item?.ssl_expires_at || null;
      if (!raw) return Number.POSITIVE_INFINITY;
      const ts = new Date(raw).getTime();
      return Number.isFinite(ts) ? ts : Number.POSITIVE_INFINITY;
    };

    const copy = [...domains];

    copy.sort((a, b) => {
      let result;
      switch (domainListSort.key) {
        case 'expiration':
          result =
            expirationTs(a) - expirationTs(b) ||
            domainFormatUrl(a.url).localeCompare(domainFormatUrl(b.url));
          break;
        case 'interval':
          result =
            (intervalOrder[String(a?.check_interval || '')] ?? 999) -
              (intervalOrder[String(b?.check_interval || '')] ?? 999) ||
            domainFormatUrl(a.url).localeCompare(domainFormatUrl(b.url));
          break;
        case 'health':
          result =
            (healthOrder[healthOf(a)] ?? 999) -
              (healthOrder[healthOf(b)] ?? 999) ||
            domainFormatUrl(a.url).localeCompare(domainFormatUrl(b.url));
          break;
        case 'az':
        default:
          result = domainFormatUrl(a.url).localeCompare(domainFormatUrl(b.url));
          break;
      }
      return domainListSort.direction === 'desc' ? -result : result;
    });

    return copy;
  }, [domains, domainListSort]);

  useEffect(() => {
    setEndpointMonitorsPage(0);
  }, [domains, domainListSort.key, domainListSort.direction]);

  const paginatedVisibleDomains = useMemo(() => {
    const start = endpointMonitorsPage * ENDPOINT_MONITORS_PAGE_SIZE;
    return visibleDomains.slice(start, start + ENDPOINT_MONITORS_PAGE_SIZE);
  }, [visibleDomains, endpointMonitorsPage]);

  const isMdUpForEndpointList = useBreakpointValue(
    { base: false, md: true },
    { fallback: 'md' }
  );

  const handleDomainListSort = key => {
    setDomainListSort(current => ({
      key,
      direction:
        current.key === key && current.direction === 'asc' ? 'desc' : 'asc',
    }));
  };

  const renderDomainSortArrow = key => (
    <Text fontSize='xs' opacity={domainListSort.key === key ? 1 : 0.3}>
      {domainListSort.key === key && domainListSort.direction === 'desc'
        ? '↓'
        : '↑'}
    </Text>
  );

  useEffect(() => {
    if (isOpen && ctxWorkspaceId) loadDomains();
  }, [isOpen, ctxWorkspaceId, loadDomains]);

  const handleAddDomain = async () => {
    if (!domainUrl.trim() || !ctxWorkspaceId) return;
    setAddingDomain(true);
    try {
      const endpointBody = {
        url: domainUrl.trim(),
        health_check_enabled: domainHealthCheck,
        check_interval: domainInterval,
        alert_after_failures: domainAlertAfter,
        contact_group_id: domainContactGroupId || null,
      };
      if (domainEndpointTokenSection.trim()) {
        endpointBody.section = domainEndpointTokenSection.trim();
      }
      await apiClient.post(
        `/api/v1/workspaces/${ctxWorkspaceId}/domains`,
        endpointBody
      );
      showSuccessMessage('Endpoint added! SSL certificate tracked.');
      setDomainUrl('');
      setDomainHealthCheck(true);
      setDomainInterval('hourly');
      setDomainAlertAfter(2);
      setDomainContactGroupId(defaultContactGroupId || '');
      setDomainEndpointTokenSection('');
      loadDomains();
      try {
        window.dispatchEvent(new CustomEvent('tt:tokens-imported'));
        window.dispatchEvent(
          new CustomEvent('tt:tokens-updated', { detail: { t: Date.now() } })
        );
      } catch (_) {}
      try {
        await Promise.all(
          TOKEN_CATEGORIES.map(cat =>
            fetchTokensForCategoryReset(cat.value, {
              workspaceId: ctxWorkspaceId,
            })
          )
        );
      } catch (err) {
        logger.error('Token list refresh after endpoint add failed', err);
      }
      try {
        const section =
          (panelQueries && panelQueries.__section) ||
          new URLSearchParams(window.location.search).get('section') ||
          '__all__';
        await fetchGlobalFacets?.({ workspaceId: ctxWorkspaceId, section });
      } catch (_) {}
    } catch (e) {
      const msg = e?.response?.data?.error || 'Failed to add endpoint';
      logger.error('Endpoint add failed:', msg);
      toast.error(msg);
    } finally {
      setAddingDomain(false);
    }
  };

  const handleDeleteDomain = async domainId => {
    try {
      await apiClient.delete(
        `/api/v1/workspaces/${ctxWorkspaceId}/domains/${domainId}`
      );
      showSuccessMessage('Endpoint monitor deleted');
      loadDomains();
      window.dispatchEvent(new CustomEvent('tt:tokens-updated'));
    } catch (e) {
      toast.error(
        e?.response?.data?.error || 'Failed to delete endpoint monitor'
      );
    }
  };

  const handleCheckDomain = async (domainId, event) => {
    event?.preventDefault?.();
    event?.currentTarget?.blur?.();
    const modalBody = document.querySelector(
      '[data-endpoint-ssl-modal-body="true"]'
    );
    const previousScrollTop = modalBody?.scrollTop;
    try {
      setCheckingDomain(domainId);
      const res = await apiClient.post(
        `/api/v1/workspaces/${ctxWorkspaceId}/domains/${domainId}/check`
      );
      const { data } = res;
      if (data.status === 'healthy') {
        showSuccessMessage(`Healthy (${data.responseMs}ms)`);
      } else {
        toast.error(
          `${data.status}: ${data.error || 'Unknown error'} (${data.responseMs}ms)`
        );
      }
      await loadDomains();
      if (modalBody && typeof previousScrollTop === 'number') {
        window.requestAnimationFrame(() => {
          modalBody.scrollTop = previousScrollTop;
        });
      }
    } catch (e) {
      toast.error(e?.response?.data?.error || 'Health check failed');
    } finally {
      setCheckingDomain(null);
    }
  };

  const handleDomainCheckerLookup = async () => {
    if (!domainCheckerInput.trim() || !ctxWorkspaceId) return;
    setDomainCheckerLoading(true);
    setDomainCheckerTruncated(false);
    setDomainCheckerImportReport(null);
    setDomainCheckerImportReportOpen(false);
    const lookupUrl = `/api/v1/workspaces/${ctxWorkspaceId}/domain-checker/lookup`;
    const lookupBody = {
      domain: domainCheckerInput.trim(),
      subfinder_all: domainCheckerSubfinderAll,
    };
    const lookupReqOpts = { timeout: DOMAIN_CHECKER_LOOKUP_TIMEOUT_MS };
    const lookupMaxAttempts = 3;
    const lookupRetriable = e => {
      if (e?.code === 'ERR_CANCELED' || e?.name === 'CanceledError')
        return false;
      const status = e?.response?.status;
      if (status == null) {
        const c = e?.code;
        return (
          c === 'ECONNABORTED' ||
          c === 'ERR_NETWORK' ||
          c === 'ETIMEDOUT' ||
          c === 'ECONNRESET' ||
          (!e?.response && c !== 'ERR_BAD_REQUEST')
        );
      }
      return status >= 500 && status < 600;
    };
    try {
      let res;
      for (let attempt = 0; attempt < lookupMaxAttempts; attempt += 1) {
        try {
          res = await apiClient.post(lookupUrl, lookupBody, lookupReqOpts);
          break;
        } catch (e) {
          const last = attempt === lookupMaxAttempts - 1;
          if (last || !lookupRetriable(e)) throw e;
          toast('Discovery is slow or the connection dropped. Retrying…', {
            icon: '⏳',
          });
          await new Promise(r => setTimeout(r, 2000 * (attempt + 1)));
        }
      }
      const items = normalizeDomainCheckerItems(res.data?.items);
      const cap = Number(res.data?.meta?.maxResults);
      const capN = Number.isFinite(cap) && cap > 0 ? cap : 500;
      startTransition(() => {
        setDomainCheckerCapCount(capN);
        setDomainCheckerTruncated(Boolean(res.data?.meta?.truncated));
        setDomainCheckerResults(items);
        setDomainCheckerPartial(Boolean(res.data?.partial));
        setDomainCheckerToolErrors(
          normalizeDomainCheckerToolErrors(res.data?.toolErrors)
        );
      });
      items.length === 0
        ? toast.error('No subdomains found for this domain.')
        : showSuccessMessage(
            `Found ${items.length} subdomain${items.length === 1 ? '' : 's'}.`
          );
    } catch (e) {
      setDomainCheckerTruncated(false);
      const code = e?.response?.data?.code;
      const retryAfter = e?.response?.data?.retry_after_seconds;
      const base =
        code === 'DOMAIN_CHECKER_RATE_LIMITED' && Number.isFinite(retryAfter)
          ? `Rate limited. Try again in about ${retryAfter}s.`
          : e?.response?.data?.error;
      toast.error(
        base ||
          'Domain checker lookup failed. Discovery tools may be slow or unavailable.'
      );
    } finally {
      setDomainCheckerLoading(false);
    }
  };

  const toggleDomainCheckerResult = useCallback(id => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const domainCheckerVisibleResults = useMemo(() => {
    return Array.isArray(domainCheckerResults)
      ? domainCheckerResults.filter(Boolean)
      : [];
  }, [domainCheckerResults]);

  const deferredDomainCheckerVisibleForTable = useDeferredValue(
    domainCheckerVisibleResults
  );

  const domainCheckerPageItems = useMemo(
    () =>
      deferredDomainCheckerVisibleForTable.slice(
        domainCheckerPage * DOMAIN_CHECKER_PAGE_SIZE,
        (domainCheckerPage + 1) * DOMAIN_CHECKER_PAGE_SIZE
      ),
    [domainCheckerPage, deferredDomainCheckerVisibleForTable]
  );

  const domainCheckerSelectAllVisibleState = useMemo(() => {
    const ids = domainCheckerVisibleResults.map(c => c?.id).filter(Boolean);
    if (ids.length === 0) return { checked: false, indeterminate: false };
    let n = 0;
    for (const id of ids) {
      if (selectedIds.has(id)) n += 1;
    }
    return {
      checked: n === ids.length,
      indeterminate: n > 0 && n < ids.length,
    };
  }, [domainCheckerVisibleResults, selectedIds]);

  const toggleDomainCheckerSelectAllVisible = useCallback(() => {
    const ids = domainCheckerVisibleResults.map(c => c?.id).filter(Boolean);
    if (ids.length === 0) return;
    setSelectedIds(prev => {
      const allOn = ids.every(id => prev.has(id));
      const next = new Set(prev);
      if (allOn) {
        for (const id of ids) next.delete(id);
      } else {
        for (const id of ids) next.add(id);
      }
      return next;
    });
  }, [domainCheckerVisibleResults]);

  const prevDomainCheckerResultsRef = useRef(null);
  useEffect(() => {
    const isNewLookup =
      domainCheckerResults !== prevDomainCheckerResultsRef.current;
    prevDomainCheckerResultsRef.current = domainCheckerResults;
    startTransition(() => {
      if (isNewLookup) {
        setSelectedIds(
          new Set(
            domainCheckerVisibleResults
              .filter(c => c?.checked && c?.id)
              .map(c => c.id)
          )
        );
      } else {
        setSelectedIds(prev => {
          const visibleIds = new Set(
            domainCheckerVisibleResults.map(c => c.id).filter(Boolean)
          );
          const next = new Set();
          for (const id of prev) if (visibleIds.has(id)) next.add(id);
          return next;
        });
      }
      setDomainCheckerPage(0);
    });
  }, [domainCheckerVisibleResults, domainCheckerResults]);

  const handleDomainCheckerImport = async () => {
    if (!ctxWorkspaceId || selectedIds.size === 0) return;
    if (domainCheckerImportInFlightRef.current) return;
    domainCheckerImportInFlightRef.current = true;
    const selected = domainCheckerVisibleResults.filter(item =>
      selectedIds.has(item.id)
    );
    setDomainCheckerImporting(true);
    setDomainCheckerImportReport(null);
    setDomainCheckerImportReportOpen(false);
    try {
      const peelDomainCheckerSelectionAfterImport = (
        importedList,
        skippedList
      ) => {
        const drop = new Set();
        for (const row of importedList || []) {
          const cid = row && (row.certificateId || row.certificate_id);
          if (cid) drop.add(String(cid));
        }
        for (const row of skippedList || []) {
          if (row && row.reason === 'duplicate' && row.id)
            drop.add(String(row.id));
        }
        if (drop.size === 0) return;
        setSelectedIds(prev => {
          const next = new Set();
          for (const id of prev) {
            if (!drop.has(String(id))) next.add(id);
          }
          return next;
        });
      };

      const payloadBase = {
        domain: domainCheckerInput.trim(),
        monitorOptions: {
          enabled: domainCheckerCreateMonitors,
          health_check_enabled: domainCheckerMonitorHealthCheck,
          check_interval: domainCheckerMonitorInterval,
          alert_after_failures: domainCheckerMonitorAlertAfter,
          contact_group_id: domainCheckerMonitorContactGroupId || null,
        },
      };
      if (domainCheckerImportSection.trim()) {
        payloadBase.tokenOptions = {
          section: domainCheckerImportSection.trim(),
        };
      }

      const mergedImported = [];
      const mergedSkipped = [];
      let monitorsCreated = 0;
      let monitorsExisting = 0;
      let chunkError = null;
      let hadNoResponseChunk = false;

      for (
        let i = 0;
        i < selected.length;
        i += DOMAIN_CHECKER_IMPORT_CHUNK_SIZE
      ) {
        const chunk = selected.slice(i, i + DOMAIN_CHECKER_IMPORT_CHUNK_SIZE);
        try {
          const res = await apiClient.post(
            `/api/v1/workspaces/${ctxWorkspaceId}/domain-checker/import`,
            { ...payloadBase, certificates: chunk },
            { timeout: DOMAIN_CHECKER_IMPORT_CHUNK_TIMEOUT_MS }
          );
          mergedImported.push(
            ...(Array.isArray(res.data?.imported)
              ? res.data.imported
              : []
            ).filter(Boolean)
          );
          mergedSkipped.push(
            ...(Array.isArray(res.data?.skipped)
              ? res.data.skipped
              : []
            ).filter(Boolean)
          );
          monitorsCreated += res.data?.monitors?.created || 0;
          monitorsExisting += res.data?.monitors?.existing || 0;
        } catch (e) {
          if (!e?.response) {
            hadNoResponseChunk = true;
            chunkError = e;
            continue;
          }
          chunkError = e;
          break;
        }
      }

      const refreshAfterDomainCheckerImport = async () => {
        try {
          window.dispatchEvent(new CustomEvent('tt:tokens-imported'));
          window.dispatchEvent(
            new CustomEvent('tt:tokens-updated', { detail: { t: Date.now() } })
          );
        } catch (_) {}
        try {
          await Promise.all(
            TOKEN_CATEGORIES.map(cat =>
              fetchTokensForCategoryReset(cat.value, {
                workspaceId: ctxWorkspaceId,
              })
            )
          );
        } catch (err) {
          logger.error(
            'Token list refresh after domain checker import failed',
            err
          );
        }
        try {
          const section =
            (panelQueries && panelQueries.__section) ||
            new URLSearchParams(window.location.search).get('section') ||
            '__all__';
          await fetchGlobalFacets?.({ workspaceId: ctxWorkspaceId, section });
        } catch (_) {}
        try {
          await loadDomains();
        } catch (_) {}
      };

      const applyImportReport = (imported, skippedList, options = {}) => {
        const safeSkipped = skippedList.filter(Boolean);
        const dnsUnreachableDetails = new Set([
          'live_certificate_dns_unresolved',
          'live_certificate_dns_temporary',
        ]);
        const unreachable = safeSkipped.filter(
          s =>
            s.reason === 'invalid_certificate' &&
            dnsUnreachableDetails.has(s.detail)
        ).length;
        const errorLike = safeSkipped.length - unreachable;
        const logLines = safeSkipped.map(s => {
          const label =
            (typeof s.subject === 'string' && s.subject.trim()) ||
            (Array.isArray(s.domains) && s.domains[0]) ||
            (typeof s.name === 'string' && s.name) ||
            s.id ||
            'host';
          const reason = s.reason || 'unknown';
          const detail = s.detail ? ` — ${s.detail}` : '';
          return `${label}: ${reason}${detail}`;
        });
        setDomainCheckerImportReport({
          unreachable,
          errorLike,
          imported,
          importedLowerBound: Boolean(options.importedLowerBound),
          logLines,
        });
        setDomainCheckerImportReportOpen(false);
      };

      if (chunkError && !hadNoResponseChunk) {
        await refreshAfterDomainCheckerImport();
        if (mergedImported.length || mergedSkipped.length) {
          peelDomainCheckerSelectionAfterImport(mergedImported, mergedSkipped);
          applyImportReport(mergedImported.length, mergedSkipped, {
            importedLowerBound: false,
          });
          toast.error(
            chunkError?.response?.data?.error || 'Failed to import SSL tokens'
          );
        } else {
          setDomainCheckerImportReport(null);
          toast.error(
            chunkError?.response?.data?.error || 'Failed to import SSL tokens'
          );
        }
      } else {
        const importedList = mergedImported;
        const skippedList = mergedSkipped;
        const imported = importedList.length;

        let summary = `Imported ${imported} SSL token${imported === 1 ? '' : 's'}`;
        if (monitorsCreated || monitorsExisting) {
          const monitorParts = [];
          if (monitorsCreated)
            monitorParts.push(
              `${monitorsCreated} new monitor${monitorsCreated === 1 ? '' : 's'}`
            );
          if (monitorsExisting)
            monitorParts.push(`${monitorsExisting} already existed`);
          summary += ` (${monitorParts.join(', ')})`;
        }
        summary += '.';
        peelDomainCheckerSelectionAfterImport(importedList, skippedList);
        showSuccessMessage(summary);

        applyImportReport(imported, skippedList, {
          importedLowerBound: hadNoResponseChunk,
        });
        if (!hadNoResponseChunk) {
          setDomainCheckerResults([]);
          setSelectedIds(new Set());
          setDomainCheckerPage(0);
          setDomainCheckerPartial(false);
          setDomainCheckerTruncated(false);
          setDomainCheckerToolErrors([]);
          setDomainCheckerInput('');
          setDomainListSort({ key: 'az', direction: 'asc' });
          await refreshAfterDomainCheckerImport();
          window.requestAnimationFrame(() => {
            const modalBody = document.querySelector(
              '[data-endpoint-ssl-modal-body="true"]'
            );
            modalBody?.scrollTo({ top: 0, behavior: 'smooth' });
          });
        } else {
          await refreshAfterDomainCheckerImport();
        }
        if (hadNoResponseChunk) {
          toast.error(
            `One or more import batches lost the response before completion. At least ${imported} token(s) are confirmed from completed batches; additional tokens may have been imported in interrupted batches. Refresh the list to verify the final total.`
          );
        }
      }
    } catch (e) {
      setDomainCheckerImportReport(null);
      const noResponse = !e?.response;
      toast.error(
        noResponse
          ? 'Connection closed before the response finished. Some tokens may already be imported; refresh the list before retrying.'
          : e?.response?.data?.error || 'Failed to import SSL tokens'
      );
    } finally {
      domainCheckerImportInFlightRef.current = false;
      setDomainCheckerImporting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleDomainModalClose}
      size='xl'
      motionPreset='none'
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW='1100px'>
        <ModalHeader {...headerProps}>
          <Text
            fontSize={{ base: 'md', md: 'lg' }}
            fontWeight='bold'
            color={modalTokens.text}
          >
            Endpoint & SSL monitoring
          </Text>
          <Text
            fontSize='sm'
            color={modalTokens.muted}
            mt={1.5}
            fontWeight='medium'
          >
            Monitor SSL certificates and endpoint health for your URLs.
          </Text>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps} data-endpoint-ssl-modal-body='true'>
          <VStack spacing={5} align='stretch'>
            <Text fontSize='sm' color={muted}>
              Monitor SSL certificates and endpoint health for your URLs. Tokens
              are auto-created for each SSL certificate detected.
            </Text>

            {domainCheckerImportReport && (
              <Box {...fieldProps} p={3} fontSize='sm'>
                <HStack justify='space-between' align='start' spacing={3}>
                  <Box>
                    <Text fontWeight='semibold'>Last import summary</Text>
                    <Text color={muted}>
                      {domainCheckerImportReport.importedLowerBound
                        ? 'At least '
                        : ''}
                      {domainCheckerImportReport.imported} SSL token
                      {domainCheckerImportReport.imported === 1 ? '' : 's'}{' '}
                      {domainCheckerImportReport.importedLowerBound
                        ? 'confirmed in completed responses'
                        : 'created'}
                      , {domainCheckerImportReport.errorLike} skipped,{' '}
                      {domainCheckerImportReport.unreachable} unreachable.
                    </Text>
                  </Box>
                  <Button
                    size='xs'
                    variant='ghost'
                    onClick={() => {
                      setDomainCheckerImportReport(null);
                      setDomainCheckerImportReportOpen(false);
                    }}
                  >
                    Dismiss
                  </Button>
                </HStack>
                {domainCheckerImportReport.logLines.length > 0 && (
                  <>
                    <Button
                      variant='link'
                      size='xs'
                      mt={1}
                      rightIcon={
                        domainCheckerImportReportOpen ? (
                          <FiChevronUp />
                        ) : (
                          <FiChevronDown />
                        )
                      }
                      onClick={() => setDomainCheckerImportReportOpen(o => !o)}
                    >
                      {domainCheckerImportReportOpen
                        ? 'Show less'
                        : 'Show more'}
                    </Button>
                    <Collapse in={domainCheckerImportReportOpen} animateOpacity>
                      <Box
                        as='pre'
                        mt={2}
                        p={2}
                        borderRadius='md'
                        bg={mobileCardBg}
                        fontSize='xs'
                        whiteSpace='pre-wrap'
                        wordBreak='break-word'
                        maxH='220px'
                        overflowY='auto'
                      >
                        {domainCheckerImportReport.logLines.join('\n')}
                      </Box>
                    </Collapse>
                  </>
                )}
              </Box>
            )}

            {domainsLoading ? (
              <Text fontSize='sm' color={muted}>
                Loading endpoints...
              </Text>
            ) : domains.length === 0 ? (
              <Alert status='info' borderRadius='md' size='sm'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>
                  No endpoints monitored yet. Add one below to start tracking
                  SSL certificates and endpoint health.
                </AlertDescription>
              </Alert>
            ) : (
              <>
                {visibleDomains.length === 0 ? (
                  <Alert status='info' borderRadius='md' size='sm'>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      No endpoints match your current filters.
                    </AlertDescription>
                  </Alert>
                ) : (
                  <>
                    {!isMdUpForEndpointList ? (
                      <Box>
                        <VStack align='stretch' spacing={3}>
                          {paginatedVisibleDomains.map(d => (
                            <Box
                              key={d.id}
                              p={4}
                              bg={mobileCardBg}
                              border='1px solid'
                              borderColor={border}
                              borderRadius='md'
                            >
                              <HStack
                                justify='space-between'
                                align='start'
                                mb={2}
                              >
                                <Box flex='1' minW='0'>
                                  <HStack spacing={1}>
                                    <Text
                                      fontWeight='semibold'
                                      fontSize='sm'
                                      wordBreak='break-all'
                                    >
                                      {domainFormatUrl(d.url)}
                                    </Text>
                                    <IconButton
                                      as='a'
                                      href={d.url}
                                      target='_blank'
                                      rel='noopener'
                                      size='xs'
                                      variant='ghost'
                                      icon={<FiExternalLink />}
                                      aria-label='Open'
                                    />
                                  </HStack>
                                  {d.ssl_issuer && (
                                    <Text fontSize='xs' color={muted}>
                                      Issuer: {d.ssl_issuer}
                                    </Text>
                                  )}
                                </Box>
                                <HStack spacing={1}>
                                  <IconButton
                                    size='xs'
                                    icon={<FiRefreshCw />}
                                    aria-label='Check now'
                                    onClick={event =>
                                      handleCheckDomain(d.id, event)
                                    }
                                    isLoading={checkingDomain === d.id}
                                  />
                                  <IconButton
                                    size='xs'
                                    icon={<FiTrash2 />}
                                    aria-label='Delete'
                                    colorScheme='red'
                                    variant='ghost'
                                    onClick={() => handleDeleteDomain(d.id)}
                                  />
                                </HStack>
                              </HStack>
                              <HStack spacing={2} flexWrap='wrap' mb={2}>
                                {domainSslBadge(d)}
                                {d.last_health_status ? (
                                  <Badge
                                    colorScheme={domainStatusColor(
                                      d.last_health_status
                                    )}
                                  >
                                    {d.last_health_status}
                                  </Badge>
                                ) : (
                                  <Badge colorScheme='gray'>Pending</Badge>
                                )}
                                <Badge variant='outline'>
                                  {d.check_interval}
                                </Badge>
                                <Badge variant='outline' colorScheme='orange'>
                                  {d.alert_after_failures || 2}x
                                </Badge>
                              </HStack>
                              <HStack spacing={4} fontSize='xs' color={muted}>
                                {d.last_health_response_ms != null && (
                                  <Text>{d.last_health_response_ms}ms</Text>
                                )}
                                {d.last_health_check_at && (
                                  <Text>
                                    {new Date(
                                      d.last_health_check_at
                                    ).toLocaleString()}
                                  </Text>
                                )}
                              </HStack>
                            </Box>
                          ))}
                        </VStack>
                      </Box>
                    ) : (
                      <Box
                        borderRadius='md'
                        border='1px solid'
                        borderColor={border}
                        overflow='auto'
                      >
                        <Table size='sm' variant='simple' tableLayout='fixed'>
                          <Thead>
                            <Tr>
                              <Th
                                w='28%'
                                cursor='pointer'
                                userSelect='none'
                                onClick={() => handleDomainListSort('az')}
                              >
                                <HStack spacing={1} justify='space-between'>
                                  <Text>Endpoint</Text>
                                  {renderDomainSortArrow('az')}
                                </HStack>
                              </Th>
                              <Th
                                whiteSpace='nowrap'
                                cursor='pointer'
                                userSelect='none'
                                onClick={() =>
                                  handleDomainListSort('expiration')
                                }
                              >
                                <HStack spacing={1} justify='space-between'>
                                  <Text>SSL</Text>
                                  {renderDomainSortArrow('expiration')}
                                </HStack>
                              </Th>
                              <Th
                                whiteSpace='nowrap'
                                cursor='pointer'
                                userSelect='none'
                                onClick={() => handleDomainListSort('health')}
                              >
                                <HStack spacing={1} justify='space-between'>
                                  <Text>Health</Text>
                                  {renderDomainSortArrow('health')}
                                </HStack>
                              </Th>
                              <Th whiteSpace='nowrap'>Response</Th>
                              <Th whiteSpace='nowrap'>Last Check</Th>
                              <Th
                                whiteSpace='nowrap'
                                cursor='pointer'
                                userSelect='none'
                                onClick={() => handleDomainListSort('interval')}
                              >
                                <HStack spacing={1} justify='space-between'>
                                  <Text>Interval</Text>
                                  {renderDomainSortArrow('interval')}
                                </HStack>
                              </Th>
                              <Th whiteSpace='nowrap'>Alert after</Th>
                              <Th
                                textAlign='right'
                                whiteSpace='nowrap'
                                width='92px'
                              ></Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {paginatedVisibleDomains.map(d => (
                              <Tr key={d.id}>
                                <Td maxW='0'>
                                  <HStack spacing={1} minW='0'>
                                    <Text
                                      fontWeight='medium'
                                      fontSize='sm'
                                      whiteSpace='normal'
                                      wordBreak='break-all'
                                      overflowWrap='anywhere'
                                      flex='1'
                                      minW='0'
                                    >
                                      {domainFormatUrl(d.url)}
                                    </Text>
                                    <Tooltip label='Open in browser'>
                                      <IconButton
                                        as='a'
                                        href={d.url}
                                        target='_blank'
                                        rel='noopener'
                                        size='xs'
                                        variant='ghost'
                                        icon={<FiExternalLink />}
                                        aria-label='Open'
                                      />
                                    </Tooltip>
                                  </HStack>
                                  {d.ssl_issuer && (
                                    <Text fontSize='2xs' color={muted}>
                                      Issuer: {d.ssl_issuer}
                                    </Text>
                                  )}
                                </Td>
                                <Td whiteSpace='nowrap'>{domainSslBadge(d)}</Td>
                                <Td whiteSpace='nowrap'>
                                  {d.last_health_status ? (
                                    <Tooltip
                                      label={
                                        d.last_health_error ||
                                        `HTTP ${d.last_health_status_code}`
                                      }
                                    >
                                      <Badge
                                        colorScheme={domainStatusColor(
                                          d.last_health_status
                                        )}
                                      >
                                        {d.last_health_status}
                                      </Badge>
                                    </Tooltip>
                                  ) : (
                                    <Badge colorScheme='gray'>Pending</Badge>
                                  )}
                                </Td>
                                <Td fontSize='xs' whiteSpace='nowrap'>
                                  {d.last_health_response_ms != null
                                    ? `${d.last_health_response_ms}ms`
                                    : '-'}
                                </Td>
                                <Td fontSize='xs' whiteSpace='nowrap'>
                                  {d.last_health_check_at
                                    ? new Date(
                                        d.last_health_check_at
                                      ).toLocaleString()
                                    : '-'}
                                </Td>
                                <Td whiteSpace='nowrap'>
                                  <Badge variant='outline'>
                                    {d.check_interval}
                                  </Badge>
                                </Td>
                                <Td>
                                  <Tooltip
                                    label={`Alert sent after ${d.alert_after_failures || 2} consecutive failures`}
                                  >
                                    <Badge
                                      variant='outline'
                                      colorScheme='orange'
                                    >
                                      {d.alert_after_failures || 2}x
                                    </Badge>
                                  </Tooltip>
                                </Td>
                                <Td textAlign='right'>
                                  <HStack spacing={1} justify='flex-end'>
                                    <Tooltip label='Run health check now'>
                                      <IconButton
                                        size='xs'
                                        icon={<FiRefreshCw />}
                                        aria-label='Check now'
                                        onClick={event =>
                                          handleCheckDomain(d.id, event)
                                        }
                                        isLoading={checkingDomain === d.id}
                                      />
                                    </Tooltip>
                                    <Tooltip label='Delete endpoint monitor'>
                                      <IconButton
                                        size='xs'
                                        icon={<FiTrash2 />}
                                        aria-label='Delete'
                                        colorScheme='red'
                                        variant='ghost'
                                        onClick={() => handleDeleteDomain(d.id)}
                                      />
                                    </Tooltip>
                                  </HStack>
                                </Td>
                              </Tr>
                            ))}
                          </Tbody>
                        </Table>
                      </Box>
                    )}

                    {visibleDomains.length > ENDPOINT_MONITORS_PAGE_SIZE && (
                      <HStack justify='center' spacing={3} pt={2}>
                        <Button
                          size='sm'
                          variant='outline'
                          isDisabled={endpointMonitorsPage <= 0}
                          onClick={() =>
                            setEndpointMonitorsPage(p => Math.max(0, p - 1))
                          }
                        >
                          Previous
                        </Button>
                        <Text fontSize='sm' color={muted}>
                          Showing{' '}
                          {endpointMonitorsPage * ENDPOINT_MONITORS_PAGE_SIZE +
                            1}
                          –
                          {Math.min(
                            (endpointMonitorsPage + 1) *
                              ENDPOINT_MONITORS_PAGE_SIZE,
                            visibleDomains.length
                          )}{' '}
                          of {visibleDomains.length}
                        </Text>
                        <Button
                          size='sm'
                          variant='outline'
                          isDisabled={
                            (endpointMonitorsPage + 1) *
                              ENDPOINT_MONITORS_PAGE_SIZE >=
                            visibleDomains.length
                          }
                          onClick={() => setEndpointMonitorsPage(p => p + 1)}
                        >
                          Next
                        </Button>
                      </HStack>
                    )}
                  </>
                )}
              </>
            )}

            <Divider />
            <Box>
              <Box mb={2}>
                <Text fontWeight='semibold' fontSize='sm'>
                  Domain checker
                </Text>
                <Text fontSize='xs' color={muted}>
                  Discovery is best-effort and limited to publicly available
                  subdomains seen by passive sources. Then import selected hosts
                  as SSL tokens and endpoint monitors.
                </Text>
              </Box>
              <HStack spacing={3} align='flex-end' flexWrap='wrap'>
                <FormControl flex={2} minW='220px'>
                  <FormLabel fontSize='sm'>Root domain</FormLabel>
                  <Input
                    size='sm'
                    value={domainCheckerInput}
                    onChange={e => setDomainCheckerInput(e.target.value)}
                    placeholder='example.com'
                  />
                </FormControl>
                <HStack align='center' spacing={1} pb={1}>
                  <Checkbox
                    size='sm'
                    colorScheme='blue'
                    isChecked={domainCheckerSubfinderAll}
                    onChange={e =>
                      setDomainCheckerSubfinderAll(e.target.checked)
                    }
                  >
                    Use all sources
                  </Checkbox>
                  <Tooltip
                    hasArrow
                    fontSize='xs'
                    maxW='280px'
                    label='subfinder -all uses every passive source and is slower than the default. Passive indexes can list stale or abandoned subdomains; SSL import may then touch hosts that no longer match your live certificates.'
                  >
                    <IconButton
                      aria-label='About subfinder all sources'
                      icon={<FiAlertTriangle />}
                      size='xs'
                      variant='ghost'
                      colorScheme='orange'
                    />
                  </Tooltip>
                </HStack>
                <Button
                  size='sm'
                  colorScheme='purple'
                  isLoading={domainCheckerLoading}
                  loadingText='Discovering...'
                  onClick={handleDomainCheckerLookup}
                  isDisabled={!domainCheckerInput.trim()}
                >
                  Discover subdomains
                </Button>
              </HStack>
              <Alert status='info' borderRadius='md' mt={3} py={2}>
                <AlertIcon />
                <AlertDescription fontSize='xs'>
                  Discovery can take up to about 5 minutes on large domains.
                  Leave this tab open while a scan runs.
                </AlertDescription>
              </Alert>
              {domainCheckerPartial && (
                <Alert status='warning' borderRadius='md' mt={3}>
                  <AlertIcon />
                  <AlertDescription fontSize='sm'>
                    Some discovery sources were unavailable. Showing partial
                    results
                    {domainCheckerToolErrors.length
                      ? ` (${domainCheckerToolErrors
                          .map(e => e?.tool || e?.message)
                          .filter(Boolean)
                          .join(', ')})`
                      : ''}
                    .
                  </AlertDescription>
                </Alert>
              )}
              {domainCheckerTruncated && (
                <Alert status='info' borderRadius='md' mt={3} py={2}>
                  <AlertIcon />
                  <AlertDescription fontSize='xs'>
                    This list is capped at {domainCheckerCapCount} hostnames per
                    discovery run. Names beyond that cap are not stored or
                    shown, so import is limited to this table.
                  </AlertDescription>
                </Alert>
              )}
              {domainCheckerResults.length > 0 && (
                <Box
                  mt={3}
                  border='1px solid'
                  borderColor={border}
                  borderRadius='md'
                  overflow='auto'
                >
                  <Table size='sm'>
                    <Thead>
                      <Tr>
                        <Th>
                          <Checkbox
                            aria-label='Select all discovered hosts (all pages)'
                            isChecked={
                              domainCheckerSelectAllVisibleState.checked
                            }
                            isIndeterminate={
                              domainCheckerSelectAllVisibleState.indeterminate
                            }
                            onChange={toggleDomainCheckerSelectAllVisible}
                          />
                        </Th>
                        <Th>Hostname</Th>
                        <Th>Domains</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {domainCheckerPageItems.map(cert => (
                        <DomainCheckerRow
                          key={cert.id}
                          cert={cert}
                          isSelected={selectedIds.has(cert.id)}
                          onToggle={toggleDomainCheckerResult}
                        />
                      ))}
                    </Tbody>
                  </Table>
                </Box>
              )}
              {domainCheckerResults.length > 0 && (
                <HStack mt={3} spacing={2} align='center' flexWrap='wrap'>
                  <Button
                    size='xs'
                    variant='outline'
                    isDisabled={domainCheckerPage === 0}
                    onClick={() => setDomainCheckerPage(p => p - 1)}
                  >
                    ← Prev
                  </Button>
                  <Text fontSize='xs' color={muted}>
                    {domainCheckerPage * DOMAIN_CHECKER_PAGE_SIZE + 1}–
                    {Math.min(
                      (domainCheckerPage + 1) * DOMAIN_CHECKER_PAGE_SIZE,
                      domainCheckerVisibleResults.length
                    )}{' '}
                    of {domainCheckerVisibleResults.length}
                    {domainCheckerResults.length !==
                    domainCheckerVisibleResults.length
                      ? ` (${domainCheckerResults.length} total)`
                      : ''}
                  </Text>
                  <Button
                    size='xs'
                    variant='outline'
                    isDisabled={
                      (domainCheckerPage + 1) * DOMAIN_CHECKER_PAGE_SIZE >=
                      domainCheckerVisibleResults.length
                    }
                    onClick={() => setDomainCheckerPage(p => p + 1)}
                  >
                    Next →
                  </Button>
                </HStack>
              )}
              {domainCheckerResults.length > 0 && (
                <Stack mt={3} spacing={3}>
                  <Alert status='info' borderRadius='md' py={2}>
                    <AlertIcon />
                    <AlertDescription fontSize='xs'>
                      Import runs in batches (up to about 5 minutes per batch on
                      slow hosts). After each run, hosts that finished importing
                      are removed from your selection so you can click Import
                      again for the rest without re-scanning.
                    </AlertDescription>
                  </Alert>
                  <FormControl maxW='480px'>
                    <FormLabel fontSize='sm'>
                      Section for imported SSL tokens
                    </FormLabel>
                    <Input
                      size='sm'
                      value={domainCheckerImportSection}
                      onChange={e =>
                        setDomainCheckerImportSection(e.target.value)
                      }
                      placeholder='Comma-separated labels (optional)'
                    />
                  </FormControl>
                  <FormControl
                    display='flex'
                    alignItems='center'
                    minW='200px'
                    maxW='360px'
                  >
                    <FormLabel mb={0} fontSize='sm'>
                      Also create endpoint monitors
                    </FormLabel>
                    <Switch
                      size='sm'
                      isChecked={domainCheckerCreateMonitors}
                      onChange={e =>
                        setDomainCheckerCreateMonitors(e.target.checked)
                      }
                    />
                  </FormControl>
                  {domainCheckerCreateMonitors && (
                    <HStack spacing={3} align='flex-end' flexWrap='wrap'>
                      <FormControl minW='140px' maxW='220px'>
                        <FormLabel fontSize='sm'>Interval</FormLabel>
                        <Select
                          size='sm'
                          value={domainCheckerMonitorInterval}
                          onChange={e =>
                            setDomainCheckerMonitorInterval(e.target.value)
                          }
                        >
                          <option value='1min'>Every 1 min</option>
                          <option value='5min'>Every 5 min</option>
                          <option value='30min'>Every 30 min</option>
                          <option value='hourly'>Hourly</option>
                          <option value='daily'>Daily</option>
                        </Select>
                      </FormControl>
                      <FormControl
                        display='flex'
                        alignItems='center'
                        minW='120px'
                        pb={1}
                      >
                        <FormLabel mb={0} fontSize='sm'>
                          Health Check
                        </FormLabel>
                        <Switch
                          size='sm'
                          isChecked={domainCheckerMonitorHealthCheck}
                          onChange={e =>
                            setDomainCheckerMonitorHealthCheck(e.target.checked)
                          }
                        />
                      </FormControl>
                      {domainCheckerMonitorHealthCheck && (
                        <FormControl minW='130px' maxW='220px'>
                          <FormLabel fontSize='sm'>
                            Alert after failures
                          </FormLabel>
                          <NumberInput
                            size='sm'
                            min={1}
                            max={10}
                            value={domainCheckerMonitorAlertAfter}
                            onChange={(_, valueAsNumber) =>
                              setDomainCheckerMonitorAlertAfter(
                                Number.isFinite(valueAsNumber)
                                  ? valueAsNumber
                                  : 2
                              )
                            }
                          >
                            <NumberInputField />
                          </NumberInput>
                        </FormControl>
                      )}
                      <FormControl minW='220px' maxW='280px'>
                        <FormLabel fontSize='sm'>Contact group</FormLabel>
                        <Select
                          size='sm'
                          value={domainCheckerMonitorContactGroupId}
                          onChange={e =>
                            setDomainCheckerMonitorContactGroupId(
                              e.target.value
                            )
                          }
                        >
                          <option value=''>Default workspace group</option>
                          {contactGroups.map(g => (
                            <option key={g.id} value={g.id}>
                              {g.name}
                            </option>
                          ))}
                        </Select>
                      </FormControl>
                    </HStack>
                  )}
                  <HStack justify='flex-end' align='center' flexWrap='wrap'>
                    <Button
                      size='sm'
                      colorScheme='purple'
                      isLoading={domainCheckerImporting}
                      isDisabled={
                        selectedIds.size === 0 || domainCheckerImporting
                      }
                      onClick={handleDomainCheckerImport}
                    >
                      Import selected ({selectedIds.size})
                    </Button>
                  </HStack>
                </Stack>
              )}
            </Box>

            <Divider />
            <Text fontWeight='semibold' fontSize='sm'>
              Add new endpoint
            </Text>
            <HStack spacing={3} align='flex-end' flexWrap='wrap'>
              <FormControl flex={2} minW='200px'>
                <FormLabel fontSize='sm'>URL</FormLabel>
                <Input
                  size='sm'
                  value={domainUrl}
                  onChange={e => setDomainUrl(e.target.value)}
                  placeholder='https://example.com'
                />
              </FormControl>
              <FormControl flex={1} minW='160px' maxW='260px'>
                <FormLabel fontSize='sm'>SSL token section</FormLabel>
                <Input
                  size='sm'
                  value={domainEndpointTokenSection}
                  onChange={e => setDomainEndpointTokenSection(e.target.value)}
                  placeholder='Optional, comma-separated'
                />
              </FormControl>
              <FormControl flex={1} minW='120px'>
                <FormLabel fontSize='sm'>Interval</FormLabel>
                <Select
                  size='sm'
                  value={domainInterval}
                  onChange={e => setDomainInterval(e.target.value)}
                >
                  <option value='1min'>Every 1 min</option>
                  <option value='5min'>Every 5 min</option>
                  <option value='30min'>Every 30 min</option>
                  <option value='hourly'>Hourly</option>
                  <option value='daily'>Daily</option>
                </Select>
              </FormControl>
              <FormControl
                display='flex'
                alignItems='center'
                minW='120px'
                pb={1}
              >
                <FormLabel mb={0} fontSize='sm'>
                  Health Check
                </FormLabel>
                <Switch
                  size='sm'
                  isChecked={domainHealthCheck}
                  onChange={e => setDomainHealthCheck(e.target.checked)}
                />
              </FormControl>
              {domainHealthCheck && (
                <FormControl minW='130px' flex={1}>
                  <FormLabel fontSize='sm'>Alert after failures</FormLabel>
                  <Select
                    size='sm'
                    value={domainAlertAfter}
                    onChange={e => setDomainAlertAfter(Number(e.target.value))}
                  >
                    <option value={1}>1 failure</option>
                    <option value={2}>2 failures</option>
                    <option value={3}>3 failures</option>
                    <option value={5}>5 failures</option>
                    <option value={10}>10 failures</option>
                  </Select>
                </FormControl>
              )}
              {Array.isArray(contactGroups) && contactGroups.length > 0 && (
                <FormControl minW='150px' flex={1}>
                  <FormLabel fontSize='sm'>Contact group</FormLabel>
                  <Select
                    size='sm'
                    value={domainContactGroupId}
                    onChange={e => setDomainContactGroupId(e.target.value)}
                  >
                    <option value=''>Workspace default</option>
                    {contactGroups.map(g => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                        {String(g.id) === String(defaultContactGroupId)
                          ? ' (default)'
                          : ''}
                      </option>
                    ))}
                  </Select>
                </FormControl>
              )}
              <Button
                size='sm'
                colorScheme='blue'
                leftIcon={<FiPlus />}
                isLoading={addingDomain}
                onClick={handleAddDomain}
                isDisabled={!domainUrl.trim()}
              >
                Add
              </Button>
            </HStack>
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            variant='outline'
            onClick={handleDomainModalClose}
            borderColor='rgba(148, 163, 184, 0.34)'
            color={modalTokens.subtleText}
            minW={{ base: '100%', sm: '104px' }}
            _hover={{
              bg: modalTokens.fieldBg,
              borderColor: modalTokens.focusBorder,
            }}
          >
            Close
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
});

export default EndpointSslMonitorModal;
