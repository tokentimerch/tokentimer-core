import React from 'react';
import {
  Modal,
  ModalOverlay,
  ModalHeader,
  ModalCloseButton,
  ModalBody,
  ModalFooter,
  Button,
  ButtonGroup,
  Box,
  VStack,
  HStack,
  Flex,
  Text,
  Alert,
  AlertIcon,
  Progress,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Input,
  Switch,
  Image,
  Badge,
  Checkbox,
  Tooltip,
  IconButton,
  useColorMode,
  Link as ChakraLink,
  Code,
  InputGroup,
  InputRightElement,
  useDisclosure,
  Select,
  FormControl,
  FormLabel,
  Divider,
} from '@chakra-ui/react';
import { logger } from '../utils/logger';
import apiClient, {
  tokenAPI,
  workspaceAPI,
  authAPI,
  azureADAPI,
  integrationAPI,
  formatDate,
  showSuccessMessage as showSuccess,
} from '../utils/apiClient';
import { showWarning } from '../utils/toast.js';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import {
  FiDownload,
  FiKey,
  FiUsers,
  FiAlertTriangle,
  FiEye,
  FiEyeOff,
} from 'react-icons/fi';
import IntegrationImportTable from './IntegrationImportTable';
import BulkIntegrationAssignment from './BulkIntegrationAssignment';
import CopyableCodeBlock from './CopyableCodeBlock';
import ImportVaultForm from './imports/ImportVaultForm';
import ImportGitLabForm from './imports/ImportGitLabForm';
import ImportGitHubForm from './imports/ImportGitHubForm';
import ImportAWSForm, {
  buildAwsAutoSyncPayload,
} from './imports/ImportAWSForm';
import ImportAzureForm from './imports/ImportAzureForm';
import ImportGCPForm from './imports/ImportGCPForm';
import { useDashboardTheme } from '../hooks/useDashboardTheme.js';
import {
  DashboardModalFrame,
  DashboardModalDescription,
  DashboardModalTitle,
  useDashboardModalProps,
} from './DashboardModalFrame.jsx';

function toKey(s) {
  try {
    return String(s || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '')
      .trim();
  } catch (_) {
    return '';
  }
}

import { dashboardModalInlineActionButtonProps } from '../styles/theme.js';

// Parse error message and extract commands for copyable display
function parseErrorMessage(errorMsg) {
  if (!errorMsg) return null;

  const msg = String(errorMsg);

  // Extract CLI commands (az, gcloud, aws, etc.)
  const commands = [];
  const commandPatterns = [
    /az account (clear|get-access-token[^\n]+?)(?=\.|$)/g,
    /az login/g,
    /gcloud auth [^\n]+?(?=\.|$)/g,
    /aws [^\n]+?(?=\.|$)/g,
  ];

  commandPatterns.forEach(pattern => {
    const matches = msg.match(pattern);
    if (matches) {
      matches.forEach(cmd => {
        if (!commands.includes(cmd.trim())) {
          commands.push(cmd.trim());
        }
      });
    }
  });

  // Extract short message (first sentence or before first newline for multi-line errors)
  // For errors with bullet points or multiple lines, use the first line as the short message
  const lines = msg.split('\n');
  const firstLine = lines[0];
  let shortMsg;
  if (firstLine.includes(':')) {
    // If first line has a colon (e.g., "Connection timeout: ..."), use whole first line
    shortMsg = firstLine;
  } else {
    // Split on specific patterns and add period only if not already present
    const splitMsg = msg.split(
      /\. (Clear cache|Generate|If this persists|Reference:)/
    )[0];
    shortMsg = splitMsg.endsWith('.') ? splitMsg : `${splitMsg}.`;
  }

  return {
    shortMessage: shortMsg,
    fullMessage: msg,
    commands: commands.length > 0 ? commands : null,
  };
}

function coerceArray(value) {
  if (Array.isArray(value)) return value;
  if (value === null || value === undefined) return null;
  const str = String(value).trim();
  if (!str) return null;
  return str
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
}

function coerceNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function coerceDateYmd(value) {
  if (value === null || value === undefined) return null;

  // Excel numeric serial (days since 1899-12-30) or JS timestamp
  const asNumber =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && /^\d+(\.\d+)?$/.test(value.trim())
        ? Number(value.trim())
        : null;
  if (asNumber !== null && Number.isFinite(asNumber)) {
    // Heuristic: Excel date serials are typically < 1e6; JS ms timestamps are > 1e11
    if (asNumber > 1e11) {
      const d = new Date(asNumber);
      if (!Number.isNaN(d.getTime())) return ymdUtc(d);
    } else {
      // Treat as Excel serial days (1900 date system)
      const excelEpoch = new Date(Date.UTC(1899, 11, 30)); // 1899-12-30
      const ms = excelEpoch.getTime() + Math.round(asNumber * 86400 * 1000);
      const d = new Date(ms);
      if (!Number.isNaN(d.getTime())) return ymdUtc(d);
    }
  }

  const s = String(value).trim();
  if (!s) return null;
  // Already YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  // YYYY/MM/DD or YYYY.MM.DD
  let m = s.match(/^\s*(\d{4})[./-](\d{1,2})[./-](\d{1,2})\s*$/);
  if (m) return padYmd(Number(m[1]), Number(m[2]), Number(m[3]));
  // DD/MM/YYYY or MM/DD/YYYY or with dashes
  m = s.match(/^\s*(\d{1,2})[./-](\d{1,2})[./-](\d{4})\s*$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    const y = Number(m[3]);
    // Disambiguate: if a > 12 then it's DD/MM/YYYY; if b > 12 then MM/DD/YYYY; else default to DD/MM/YYYY
    if (a > 12 || (a <= 12 && b <= 12 && a >= b)) return padYmd(y, b, a);
    return padYmd(y, a, b);
  }
  // Fallback to Date parsing
  const d = new Date(s);
  if (!Number.isNaN(d.getTime())) return ymdUtc(d);
  // Give backend the original value (will error if invalid)
  return s;
}

function ymdUtc(d) {
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

function padYmd(y, m, d) {
  const mm = String(Math.max(1, Math.min(12, m))).padStart(2, '0');
  const dd = String(Math.max(1, Math.min(31, d))).padStart(2, '0');
  return `${y}-${mm}-${dd}`;
}

function normalizeRow(raw) {
  // Build a normalized key map
  const map = {};
  try {
    Object.keys(raw || {}).forEach(k => {
      map[toKey(k)] = raw[k];
    });
  } catch (_) {}

  const pick = (...alts) => {
    for (const a of alts) {
      const v = map[toKey(a)];
      if (v !== undefined) return v;
    }
    return undefined;
  };

  const expiresAt = pick(
    'expiresAt',
    'expiry',
    'expiration',
    'expires_at',
    'expiredate'
  );
  const keySize = pick('keysize', 'key_size', 'bits');
  const cost = pick('cost', 'price', 'amount');

  const domains = pick('domains', 'domain', 'domainlist');

  const renewRaw = pick(
    'renewal_date',
    'renewdate',
    'renewaldate',
    'renewal-date',
    'renewal date'
  );
  const row = {
    name: pick('name', 'token', 'title'),
    type: pick('type'),
    category: pick('category', 'cat'),
    expiresAt: coerceDateYmd(expiresAt),
    section: coerceArray(pick('section', 'label', 'group')),
    domains: coerceArray(domains),
    location: pick('location', 'path', 'store'),
    used_by: pick('used_by', 'usedby', 'service', 'application'),
    issuer: pick('issuer', 'authority', 'ca'),
    serial_number: pick('serial_number', 'serial', 'sn'),
    subject: pick('subject', 'cn', 'subjectdn'),
    key_size: coerceNumber(keySize),
    algorithm: pick('algorithm', 'algo'),
    license_type: pick('license_type', 'licencetype', 'licensetype'),
    vendor: pick('vendor', 'provider'),
    cost: coerceNumber(cost),
    renewal_url: pick('renewal_url', 'renewurl'),
    renewal_date: coerceDateYmd(renewRaw),
    contacts: pick('contacts', 'contact'),
    description: pick('description', 'desc', 'notes_short'),
    notes: pick('notes', 'notes_long'),
    contact_group_id: pick('contact_group_id', 'contactgroup', 'groupid'),
    privileges: pick('privileges', 'scopes', 'permissions', 'rights'),
    last_used: coerceDateYmd(
      pick('last_used', 'lastused', 'last_used_at', 'lastusedat')
    ),
    imported_at: coerceDateYmd(pick('imported_at', 'imported', 'import_date')),
    created_at: coerceDateYmd(
      pick('created_at', 'created', 'creation_date', 'creationdate')
    ),
  };

  // Remove empty strings
  Object.keys(row).forEach(k => {
    if (row[k] === '') row[k] = null;
  });
  // Strictly nullify renewal_date if not YYYY-MM-DD
  if (
    typeof row.renewal_date === 'string' &&
    !/^\d{4}-\d{2}-\d{2}$/.test(row.renewal_date)
  ) {
    row.renewal_date = null;
  }
  return row;
}

async function parseFile(file) {
  const name = (file && file.name) || '';
  const lower = name.toLowerCase();

  if (lower.endsWith('.csv')) {
    const papaparseMod = await import('papaparse');
    const Papa = papaparseMod.default ?? papaparseMod;
    return new Promise((resolve, reject) => {
      try {
        Papa.parse(file, {
          header: true,
          skipEmptyLines: true,
          complete: results => {
            try {
              const fields =
                results && results.meta && Array.isArray(results.meta.fields)
                  ? results.meta.fields.map(f =>
                      String(f || '')
                        .toLowerCase()
                        .trim()
                    )
                  : [];
              // Detect headerless CSV: required headers not present at all
              const requiredSynonyms = [
                ['name'],
                ['category'],
                ['type'],
                [
                  'expiresat',
                  'expiry',
                  'expiration',
                  'expires_at',
                  'expiredate',
                ],
              ];
              const hasAnyRequired = requiredSynonyms.every(group =>
                group.some(g => fields.includes(g))
              );

              if (hasAnyRequired) {
                return resolve(results.data || []);
              }

              // Fallback: parse again without headers and map first 4 columns
              Papa.parse(file, {
                header: false,
                skipEmptyLines: true,
                complete: r2 => {
                  try {
                    const rows = Array.isArray(r2.data) ? r2.data : [];
                    const mapped = rows
                      .map(row => (Array.isArray(row) ? row : []))
                      .map(cols => ({
                        name: cols[0],
                        category: cols[1],
                        type: cols[2],
                        expiresAt: cols[3],
                      }))
                      // Filter obviously empty rows
                      .filter(obj =>
                        Object.values(obj).some(
                          v => String(v || '').trim().length > 0
                        )
                      );
                    resolve(mapped);
                  } catch (e) {
                    resolve(results.data || []);
                  }
                },
                error: _err => resolve(results.data || []),
              });
            } catch (_) {
              resolve(results.data || []);
            }
          },
          error: err => reject(err),
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  if (lower.endsWith('.xlsx') || lower.endsWith('.xls')) {
    const xlsxMod = await import('xlsx');
    const XLSX = xlsxMod.default ?? xlsxMod;
    const buf = await file.arrayBuffer();
    const wb = XLSX.read(buf, { type: 'array' });
    const sheetName = wb.SheetNames && wb.SheetNames[0];
    const ws = sheetName ? wb.Sheets[sheetName] : null;
    if (!ws) return [];
    return XLSX.utils.sheet_to_json(ws, { defval: '' });
  }

  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) {
    const jsyamlMod = await import('js-yaml');
    const jsyaml = jsyamlMod.default ?? jsyamlMod;
    const text = await file.text();
    const doc = jsyaml.load(text);
    if (Array.isArray(doc)) return doc;
    if (doc && Array.isArray(doc.items)) return doc.items;
    if (doc && Array.isArray(doc.tokens)) return doc.tokens;
    return [];
  }

  if (lower.endsWith('.json')) {
    const text = await file.text();
    const data = JSON.parse(text);
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.items)) return data.items;
    if (data && Array.isArray(data.tokens)) return data.tokens;
    return [];
  }

  throw new Error(
    'Unsupported file type. Use .csv, .xlsx, .json, .yaml, or .yml'
  );
}

async function importWithConcurrency(
  rows,
  workspaceId,
  onProgress,
  abortSignal,
  maxConcurrency = 4,
  defaultGroupId = null
) {
  const created = [];
  const updated = [];
  const errors = [];
  let index = 0;
  let running = 0;

  return await new Promise(resolve => {
    const launchNext = () => {
      if (abortSignal && abortSignal.aborted) return finalize();
      while (running < maxConcurrency && index < rows.length) {
        const currentIndex = index++;
        const raw = rows[currentIndex];
        const payload = normalizeRow(raw);
        payload.workspace_id = workspaceId;
        if (
          (payload.contact_group_id === undefined ||
            payload.contact_group_id === null ||
            String(payload.contact_group_id).trim() === '') &&
          defaultGroupId
        ) {
          payload.contact_group_id = String(defaultGroupId);
        }

        running++;
        tokenAPI
          .createToken(payload)
          .then(tok => {
            // Check if token was updated (status 200) or created (status 201)
            // The API returns 200 for updates, 201 for creates
            // We can't distinguish from the response, so we'll track all as created
            // and let the backend handle it
            created.push(tok);
            onProgress &&
              onProgress({
                done: created.length + updated.length + errors.length,
                total: rows.length,
              });
          })
          .catch(async err => {
            // Check if it's a duplicate token error
            // The error can be:
            // 1. A plain object with code === 'DUPLICATE_TOKEN' (thrown directly from API client)
            // 2. An Error object with code === 'DUPLICATE_TOKEN'
            // 3. An Error object with message containing duplicate indicators
            // 4. The error message format: "A token named X already exists...will be updated"
            const errorMessage = err?.message || err?.error || String(err);
            const errorCode = err?.code;
            const isDuplicateError =
              errorCode === 'DUPLICATE_TOKEN' ||
              (errorMessage &&
                typeof errorMessage === 'string' &&
                (errorMessage.includes('already exists') ||
                  errorMessage.includes('Creating this token will update') ||
                  errorMessage.includes('will be updated') ||
                  errorMessage.includes('already exists in this workspace')));

            if (isDuplicateError) {
              // Automatically update the existing token
              try {
                const updatedToken = await tokenAPI.createToken(
                  { ...payload, confirm_duplicate: true },
                  true
                );
                updated.push(updatedToken);
                onProgress &&
                  onProgress({
                    done: created.length + updated.length + errors.length,
                    total: rows.length,
                  });
              } catch (updateErr) {
                // If update also fails, add to errors
                errors.push({
                  index: currentIndex,
                  error:
                    updateErr?.message || updateErr?.error || String(updateErr),
                });
                onProgress &&
                  onProgress({
                    done: created.length + updated.length + errors.length,
                    total: rows.length,
                  });
              }
            } else {
              errors.push({ index: currentIndex, error: errorMessage });
              onProgress &&
                onProgress({
                  done: created.length + updated.length + errors.length,
                  total: rows.length,
                });
            }
          })
          .finally(() => {
            running--;
            if (
              created.length + updated.length + errors.length >=
              rows.length
            ) {
              finalize();
            } else {
              launchNext();
            }
          });
      }
    };

    const finalize = () => resolve({ created, updated, errors });
    launchNext();
  });
}

// Helper function to check duplicates for a list of items
async function checkDuplicatesForItems(items, workspaceId) {
  if (!workspaceId || !items || items.length === 0) return new Set();

  try {
    const checkItems = items.map(item => ({
      name: item.name,
      location: item.location || null,
    }));
    const duplicateCheck = await integrationAPI.checkDuplicates({
      workspaceId,
      items: checkItems,
    });

    if (duplicateCheck.duplicate_count > 0) {
      const duplicateSet = new Set();
      duplicateCheck.duplicates.forEach(dup => {
        items.forEach((item, idx) => {
          if (
            item.name === dup.name &&
            (item.location || null) === (dup.location || null)
          ) {
            duplicateSet.add(idx);
          }
        });
      });
      return duplicateSet;
    }
  } catch (e) {
    logger.error('Duplicate check failed:', e);
  }
  return new Set();
}

// Helper functions to get details for each integration type
function _getVaultItemDetails(item) {
  const details = [];
  if (item.mount || item.path) {
    details.push({
      label: 'Path',
      value: `${item.mount || ''}${item.path || ''}`,
    });
  }
  if (item.issuer) {
    details.push({ label: 'Issuer', value: item.issuer });
  }
  if (item.subject) {
    details.push({ label: 'Subject', value: item.subject, maxLines: 2 });
  }
  return details;
}

function _getGitLabItemDetails(item) {
  const details = [];
  if (item.project_name) {
    details.push({ label: 'Project', value: item.project_name });
  }
  if (item.scopes && item.scopes.length > 0) {
    const scopes = Array.isArray(item.scopes)
      ? item.scopes.join(', ')
      : item.scopes;
    details.push({ label: 'Scopes', value: scopes, maxLines: 2 });
  }
  if (item.last_used_at) {
    details.push({ label: 'Last Used', value: formatDate(item.last_used_at) });
  }
  if (item.created_at) {
    details.push({ label: 'Created', value: formatDate(item.created_at) });
  }
  if (item.location) {
    details.push({ label: 'Location', value: item.location });
  }
  return details;
}

function _getGitHubItemDetails(item) {
  const details = [];
  if (item.repository) {
    details.push({ label: 'Repository', value: item.repository });
  } else {
    details.push({
      label: 'Level',
      value: 'User-level',
      badge: true,
      badgeColor: 'purple',
    });
  }
  if (item.scopes && item.scopes.length > 0) {
    const scopes = Array.isArray(item.scopes)
      ? item.scopes.join(', ')
      : item.scopes;
    details.push({ label: 'Scopes', value: scopes, maxLines: 2 });
  }
  if (item.last_used_at) {
    details.push({ label: 'Last Used', value: formatDate(item.last_used_at) });
  }
  if (item.created_at) {
    details.push({ label: 'Created', value: formatDate(item.created_at) });
  }
  if (item.location) {
    details.push({ label: 'Location', value: item.location });
  }
  return details;
}

function _getAWSItemDetails(item) {
  const details = [];
  if (item.domains) {
    const domains = Array.isArray(item.domains)
      ? item.domains.join(', ')
      : item.domains;
    details.push({ label: 'Domains', value: domains, maxLines: 2 });
  }
  if (item.issuer) {
    details.push({ label: 'Issuer', value: item.issuer });
  }
  if (item.user_name) {
    details.push({ label: 'User', value: item.user_name });
  }
  if (item.last_used_at) {
    details.push({ label: 'Last Used', value: formatDate(item.last_used_at) });
  }
  if (item.created_at) {
    details.push({ label: 'Created', value: formatDate(item.created_at) });
  }
  if (item.description) {
    details.push({ label: 'Info', value: item.description, maxLines: 2 });
  }
  if (item.location) {
    details.push({ label: 'Location', value: item.location });
  }
  return details;
}

function _getAzureItemDetails(item) {
  const details = [];
  if (item.issuer) {
    details.push({ label: 'Issuer', value: item.issuer });
  }
  if (item.subject) {
    details.push({ label: 'Subject', value: item.subject, maxLines: 2 });
  }
  if (item.location) {
    details.push({ label: 'Location', value: item.location });
  }
  return details;
}

function getAzureADItemDetails(item) {
  const details = [];
  if (item.app_id) {
    details.push({ label: 'App ID', value: item.app_id });
  }
  if (item.description) {
    details.push({ label: 'Info', value: item.description, maxLines: 2 });
  }
  if (item.location) {
    details.push({ label: 'Location', value: item.location });
  }
  return details;
}

function _getGCPItemDetails(item) {
  const details = [];
  if (item.description) {
    details.push({ label: 'Info', value: item.description, maxLines: 2 });
  }
  if (item.location) {
    details.push({ label: 'Location', value: item.location });
  }
  return details;
}

function dispatchNotificationsRefresh() {
  try {
    window.dispatchEvent(new CustomEvent('tt:notifications-refresh'));
  } catch (_) {
    /* ignore */
  }
}

const AUTO_SYNC_POLL_INTERVAL_MS = 3000;
const AUTO_SYNC_POLL_TIMEOUT_MS = 5 * 60 * 1000;

async function pollAutoSyncAfterRun({
  workspaceId,
  provider,
  baselineLastSyncAt,
  onUpdate,
  isCancelled,
}) {
  const deadline = Date.now() + AUTO_SYNC_POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (isCancelled()) return 'cancelled';
    await new Promise(resolve =>
      setTimeout(resolve, AUTO_SYNC_POLL_INTERVAL_MS)
    );
    if (isCancelled()) return 'cancelled';
    const res = await apiClient.get(
      `/api/v1/workspaces/${workspaceId}/auto-sync`
    );
    const configs = res.data?.items || [];
    const cfg = configs.find(c => c.provider === provider) || false;
    onUpdate(cfg);
    if (!cfg || !cfg.id) return 'missing';
    const completed =
      cfg.last_sync_at &&
      String(cfg.last_sync_at) !== String(baselineLastSyncAt ?? '');
    if (completed) {
      return cfg.last_sync_status || 'unknown';
    }
  }
  return 'timeout';
}

export default function ImportTokensModal({
  isOpen,
  onClose,
  onImported,
  openRequest,
  onOpenRequestHandled,
}) {
  const { workspaceId } = useWorkspace();
  const { colorMode } = useColorMode();
  const isLight = colorMode === 'light';

  const { border, muted } = useDashboardTheme();
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    fieldProps,
    outlineButtonProps,
    primaryButtonProps,
    dangerButtonProps,
    tokens: modalTokens,
  } = useDashboardModalProps();

  // Timezone list with fallback for older browsers missing Intl.supportedValuesOf
  const timezoneList = React.useMemo(() => {
    try {
      return Intl.supportedValuesOf('timeZone');
    } catch {
      return [
        'UTC',
        'America/New_York',
        'America/Chicago',
        'America/Denver',
        'America/Los_Angeles',
        'America/Sao_Paulo',
        'America/Toronto',
        'Europe/London',
        'Europe/Paris',
        'Europe/Berlin',
        'Europe/Zurich',
        'Europe/Amsterdam',
        'Europe/Madrid',
        'Europe/Rome',
        'Europe/Stockholm',
        'Europe/Warsaw',
        'Europe/Moscow',
        'Asia/Dubai',
        'Asia/Kolkata',
        'Asia/Shanghai',
        'Asia/Tokyo',
        'Asia/Singapore',
        'Asia/Hong_Kong',
        'Asia/Seoul',
        'Australia/Sydney',
        'Australia/Melbourne',
        'Pacific/Auckland',
        'Africa/Johannesburg',
        'Africa/Cairo',
      ];
    }
  }, []);

  const [source, setSource] = React.useState('file'); // 'file' | 'vault' | 'gitlab' | 'github' | 'aws' | 'azure' | 'azure-ad' | 'gcp'
  const [isViewer, setIsViewer] = React.useState(false);
  // Integration quota state
  const [integrationQuota, setIntegrationQuota] = React.useState({
    used: 0,
    limit: null,
    remaining: null,
  });
  const [_file, setFile] = React.useState(null);
  const [rows, setRows] = React.useState([]);
  const [selectedRowsFile, setSelectedRowsFile] = React.useState(new Set());
  const [parsing, setParsing] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [failedRows, setFailedRows] = React.useState([]);
  const [isImporting, setIsImporting] = React.useState(false);
  const [progress, setProgress] = React.useState({ done: 0, total: 0 });
  const abortRef = React.useRef(null);
  const fileInputRef = React.useRef(null);
  const vaultFormRef = React.useRef(null);
  const gitlabFormRef = React.useRef(null);
  const githubFormRef = React.useRef(null);
  const awsFormRef = React.useRef(null);
  const azureFormRef = React.useRef(null);
  const gcpFormRef = React.useRef(null);
  const [fileName, setFileName] = React.useState('');

  // Vault integration state
  const [vaultAddress, setVaultAddress] = React.useState(() => {
    try {
      return localStorage.getItem('tt_vault_address') || '';
    } catch (_) {
      return '';
    }
  });
  const [vaultToken, setVaultToken] = React.useState('');
  const [includeKV, setIncludeKV] = React.useState(() => {
    try {
      return (localStorage.getItem('tt_vault_include_kv') || 'true') === 'true';
    } catch (_) {
      return true;
    }
  });
  const [includePKI, setIncludePKI] = React.useState(() => {
    try {
      return (
        (localStorage.getItem('tt_vault_include_pki') || 'true') === 'true'
      );
    } catch (_) {
      return true;
    }
  });
  const maxItemsPerMount = 1000; // Fixed high default to avoid limiting results
  const [pathPrefix, setPathPrefix] = React.useState(() => {
    try {
      return localStorage.getItem('tt_vault_path_prefix') || '';
    } catch (_) {
      return '';
    }
  });
  const [isScanning, setIsScanning] = React.useState(false);
  const [scanSucceededFor, setScanSucceededFor] = React.useState(new Set()); // tracks which sources had a successful scan
  const [_mounts, setMounts] = React.useState([]);
  const [_vaultItems, setVaultItems] = React.useState([]);
  const [_summary, setSummary] = React.useState([]);
  const [_vaultDefaults, setVaultDefaults] = React.useState({
    category: 'general',
    type: 'other',
  });
  const [contactGroups, setContactGroups] = React.useState([]);

  // Shared bulk assignment state (used across all integrations)
  const [bulkSection, setBulkSection] = React.useState('');
  const [bulkContactGroupId, setBulkContactGroupId] = React.useState('');

  const [_selectedRowsVault, setSelectedRowsVault] = React.useState(new Set());

  // GitLab integration state
  const [gitlabBaseUrl, setGitlabBaseUrl] = React.useState(() => {
    try {
      return localStorage.getItem('tt_gitlab_baseurl') || 'https://gitlab.com';
    } catch (_) {
      return 'https://gitlab.com';
    }
  });
  const [gitlabToken, _setGitlabToken] = React.useState('');
  const [_gitlabItems, _setGitlabItems] = React.useState([]);
  const [_gitlabSummary, _setGitlabSummary] = React.useState([]);
  // GitLab scan filters
  const [gitlabIncludePATs, setGitlabIncludePATs] = React.useState(true);
  const [gitlabIncludeProjectTokens, setGitlabIncludeProjectTokens] =
    React.useState(true);
  const [gitlabIncludeGroupTokens, setGitlabIncludeGroupTokens] =
    React.useState(true);
  const [gitlabIncludeDeployTokens, setGitlabIncludeDeployTokens] =
    React.useState(true);
  const [gitlabIncludeSSHKeys, setGitlabIncludeSSHKeys] = React.useState(false);
  const [gitlabExcludeUserPATs, setGitlabExcludeUserPATs] =
    React.useState(true);
  const [gitlabIncludeExpired, setGitlabIncludeExpired] = React.useState(false);
  const [gitlabIncludeRevoked, setGitlabIncludeRevoked] = React.useState(false);
  const [_selectedRowsGitlab, setSelectedRowsGitlab] = React.useState(
    new Set()
  );

  // GitHub integration state
  const [githubBaseUrl, setGithubBaseUrl] = React.useState(() => {
    try {
      return (
        localStorage.getItem('tt_github_baseurl') || 'https://api.github.com'
      );
    } catch (_) {
      return 'https://api.github.com';
    }
  });
  const [githubToken, _setGithubToken] = React.useState('');
  const [_githubItems, _setGithubItems] = React.useState([]);
  const [_githubSummary, _setGithubSummary] = React.useState([]);
  // GitHub scan filters
  const [githubIncludeTokens, setGithubIncludeTokens] = React.useState(true);
  const [githubIncludeSSHKeys, setGithubIncludeSSHKeys] = React.useState(false);
  const [githubIncludeDeployKeys, setGithubIncludeDeployKeys] =
    React.useState(true);
  const [githubIncludeSecrets, setGithubIncludeSecrets] = React.useState(true);
  const [_selectedRowsGithub, setSelectedRowsGithub] = React.useState(
    new Set()
  );

  // AWS integration state
  const [awsAccessKeyId, _setAwsAccessKeyId] = React.useState('');
  const [awsSecretAccessKey, _setAwsSecretAccessKey] = React.useState('');
  const [awsRegion, setAwsRegion] = React.useState('us-east-1');
  const [_awsDetectedRegions, _setAwsDetectedRegions] = React.useState([]);
  const [awsAutoSyncScanParams, setAwsAutoSyncScanParams] =
    React.useState(null);
  const [_awsDetectionResults, _setAwsDetectionResults] = React.useState(null);
  const [_awsIamInfo, _setAwsIamInfo] = React.useState(null);
  const [_awsDetecting, _setAwsDetecting] = React.useState(false);
  const [_awsItems, _setAwsItems] = React.useState([]);
  const [_awsSummary, _setAwsSummary] = React.useState([]);
  const [_selectedRowsAws, setSelectedRowsAws] = React.useState(new Set());

  // Azure integration state
  const [azureVaultUrl, setAzureVaultUrl] = React.useState('');
  const [azureToken, _setAzureToken] = React.useState('');
  const [_azureItems, _setAzureItems] = React.useState([]);
  const [_azureSummary, _setAzureSummary] = React.useState([]);
  const [_selectedRowsAzure, setSelectedRowsAzure] = React.useState(new Set());

  // GCP integration state
  const [gcpProjectId, setGcpProjectId] = React.useState('');
  const [gcpAccessToken, _setGcpAccessToken] = React.useState('');
  const [_gcpItems, _setGcpItems] = React.useState([]);
  const [_gcpSummary, _setGcpSummary] = React.useState([]);
  const [_selectedRowsGcp, setSelectedRowsGcp] = React.useState(new Set());

  // Azure AD state
  const [azureADToken, setAzureADToken] = React.useState('');
  const [azureADIncludeApps, setAzureADIncludeApps] = React.useState(true);
  const [azureADIncludeSPs, setAzureADIncludeSPs] = React.useState(true);
  const [azureADItems, setAzureADItems] = React.useState([]);
  const [azureADSummary, setAzureADSummary] = React.useState([]);
  const [selectedRowsAzureAD, setSelectedRowsAzureAD] = React.useState(
    new Set()
  );

  // Show/hide toggle for secret fields
  const [showSecrets, setShowSecrets] = React.useState({});
  const toggleSecret = key =>
    setShowSecrets(prev => ({ ...prev, [key]: !prev[key] }));

  // Duplicate detection state for all imports
  const [fileDuplicates, setFileDuplicates] = React.useState(new Set()); // Set of row indices that are duplicates
  const [_vaultDuplicates, setVaultDuplicates] = React.useState(new Set());
  const [_gitlabDuplicates, setGitlabDuplicates] = React.useState(new Set());
  const [_githubDuplicates, setGithubDuplicates] = React.useState(new Set());
  const [_awsDuplicates, setAwsDuplicates] = React.useState(new Set());
  const [_azureDuplicates, setAzureDuplicates] = React.useState(new Set());
  const [_gcpDuplicates, setGcpDuplicates] = React.useState(new Set());
  const [azureADDuplicates, setAzureADDuplicates] = React.useState(new Set());

  // Auto-sync state
  const [autoSyncConfig, setAutoSyncConfig] = React.useState(null); // null = not loaded, false = not exists, object = exists
  const [savingAutoSync, setSavingAutoSync] = React.useState(false);
  const [runningAutoSyncNow, setRunningAutoSyncNow] = React.useState(false);
  const autoSyncPollCancelRef = React.useRef(false);

  // Available providers in core
  const CORE_AUTO_SYNC_PROVIDERS = ['github', 'gitlab'];
  const isAutoSyncAllowed = CORE_AUTO_SYNC_PROVIDERS.includes(source);
  const hasAutoSync = autoSyncConfig && autoSyncConfig.id;
  const autoSyncTokenPlaceholder = hasAutoSync
    ? 'Credentials saved for auto-sync'
    : null;
  const [integrationSubTab, setIntegrationSubTab] = React.useState('scan');
  const [pendingManageTab, setPendingManageTab] = React.useState(false);
  const autoSyncManageMode =
    integrationSubTab === 'manage' && hasAutoSync && source !== 'file';

  React.useEffect(
    () => () => {
      autoSyncPollCancelRef.current = true;
    },
    []
  );

  React.useEffect(() => {
    if (isOpen) {
      autoSyncPollCancelRef.current = false;
      return undefined;
    }
    autoSyncPollCancelRef.current = true;
    setRunningAutoSyncNow(false);
    return undefined;
  }, [isOpen]);

  // Load auto-sync config when source changes and restore form fields from scan_params
  React.useEffect(() => {
    if (!workspaceId || source === 'file') {
      setAutoSyncConfig(null);
      return;
    }
    (async () => {
      try {
        const res = await apiClient.get(
          `/api/v1/workspaces/${workspaceId}/auto-sync`
        );
        const configs = res.data?.items || [];
        const existing = configs.find(c => c.provider === source);
        setAutoSyncConfig(existing || false);

        // Restore non-secret form fields from scan_params when auto-sync is already configured
        if (existing && existing.scan_params) {
          const sp = existing.scan_params;
          switch (source) {
            case 'github':
              if (sp.baseUrl) setGithubBaseUrl(sp.baseUrl);
              if (sp.include) {
                if (sp.include.tokens !== undefined)
                  setGithubIncludeTokens(sp.include.tokens);
                if (sp.include.sshKeys !== undefined)
                  setGithubIncludeSSHKeys(sp.include.sshKeys);
                if (sp.include.deployKeys !== undefined)
                  setGithubIncludeDeployKeys(sp.include.deployKeys);
                if (sp.include.secrets !== undefined)
                  setGithubIncludeSecrets(sp.include.secrets);
              }
              break;
            case 'gitlab':
              if (sp.baseUrl) setGitlabBaseUrl(sp.baseUrl);
              if (sp.filters) {
                if (sp.filters.includePATs !== undefined)
                  setGitlabIncludePATs(sp.filters.includePATs);
                if (sp.filters.includeProjectTokens !== undefined)
                  setGitlabIncludeProjectTokens(
                    sp.filters.includeProjectTokens
                  );
                if (sp.filters.includeGroupTokens !== undefined)
                  setGitlabIncludeGroupTokens(sp.filters.includeGroupTokens);
                if (sp.filters.includeDeployTokens !== undefined)
                  setGitlabIncludeDeployTokens(sp.filters.includeDeployTokens);
                if (sp.filters.includeSSHKeys !== undefined)
                  setGitlabIncludeSSHKeys(sp.filters.includeSSHKeys);
                if (sp.filters.excludeUserPATs !== undefined)
                  setGitlabExcludeUserPATs(sp.filters.excludeUserPATs);
                if (sp.filters.includeExpired !== undefined)
                  setGitlabIncludeExpired(sp.filters.includeExpired);
                if (sp.filters.includeRevoked !== undefined)
                  setGitlabIncludeRevoked(sp.filters.includeRevoked);
              }
              break;
            case 'vault':
              if (sp.address) setVaultAddress(sp.address);
              if (sp.include) {
                if (sp.include.kv !== undefined) setIncludeKV(sp.include.kv);
                if (sp.include.pki !== undefined) setIncludePKI(sp.include.pki);
              }
              if (sp.pathPrefix !== undefined) setPathPrefix(sp.pathPrefix);
              break;
            case 'aws':
              if (
                sp.scanMode === 'all-regions' ||
                sp.region === 'all-regions'
              ) {
                setAwsRegion('all-regions');
              } else if (sp.scanMode === 'global' || sp.region === 'global') {
                setAwsRegion('global');
              } else if (sp.region) {
                setAwsRegion(sp.region);
              }
              if (Array.isArray(sp.detectedRegions)) {
                _setAwsDetectedRegions(sp.detectedRegions);
              }
              setAwsAutoSyncScanParams(sp);
              break;
            case 'azure':
              if (sp.vaultUrl) setAzureVaultUrl(sp.vaultUrl);
              break;
            case 'azure-ad':
              if (sp.include) {
                if (sp.include.applications !== undefined)
                  setAzureADIncludeApps(sp.include.applications);
                if (sp.include.servicePrincipals !== undefined)
                  setAzureADIncludeSPs(sp.include.servicePrincipals);
              }
              break;
            case 'gcp':
              if (sp.projectId) setGcpProjectId(sp.projectId);
              break;
          }
        } else if (source === 'aws') {
          setAwsAutoSyncScanParams(null);
        }
      } catch (_) {
        setAutoSyncConfig(false);
      }
    })();
  }, [workspaceId, source]);

  React.useEffect(() => {
    if (!isOpen || !openRequest?.provider) return;
    if (openRequest.integrationSubTab === 'manage') {
      setPendingManageTab(true);
    }
    setSource(openRequest.provider);
    onOpenRequestHandled?.();
  }, [isOpen, openRequest, onOpenRequestHandled]);

  React.useEffect(() => {
    if (pendingManageTab) return;
    setIntegrationSubTab('scan');
    // Only reset when the provider changes, not when pendingManageTab clears after deep-link
  }, [source]);

  React.useEffect(() => {
    if (!pendingManageTab) return;
    if (autoSyncConfig === false) {
      setPendingManageTab(false);
      return;
    }
    if (!hasAutoSync) return;
    setIntegrationSubTab('manage');
    setPendingManageTab(false);
  }, [pendingManageTab, hasAutoSync, autoSyncConfig]);

  // Build credentials from current form state
  const getAutoSyncCredentials = () => {
    let credentials = {};
    let scanParams = {};
    switch (source) {
      case 'github': {
        const formCreds = githubFormRef.current?.getCredentials();
        credentials = formCreds?.credentials ?? {
          baseUrl: githubBaseUrl || 'https://api.github.com',
          token: githubToken,
        };
        scanParams = formCreds?.scanParams ?? {
          baseUrl: githubBaseUrl || 'https://api.github.com',
          include: {
            tokens: githubIncludeTokens,
            sshKeys: githubIncludeSSHKeys,
            deployKeys: githubIncludeDeployKeys,
            secrets: githubIncludeSecrets,
          },
        };
        break;
      }
      case 'gitlab': {
        const formCreds = gitlabFormRef.current?.getCredentials();
        credentials = formCreds?.credentials ?? {
          baseUrl: gitlabBaseUrl || 'https://gitlab.com',
          token: gitlabToken,
        };
        scanParams = formCreds?.scanParams ?? {
          baseUrl: gitlabBaseUrl || 'https://gitlab.com',
          include: { tokens: true, keys: true },
          filters: {
            includePATs: gitlabIncludePATs,
            includeProjectTokens: gitlabIncludeProjectTokens,
            includeGroupTokens: gitlabIncludeGroupTokens,
            includeDeployTokens: gitlabIncludeDeployTokens,
            includeSSHKeys: gitlabIncludeSSHKeys,
            excludeUserPATs: gitlabExcludeUserPATs,
            includeExpired: gitlabIncludeExpired,
            includeRevoked: gitlabIncludeRevoked,
          },
        };
        break;
      }
      case 'vault': {
        const formCreds = vaultFormRef.current?.getCredentials();
        credentials = formCreds?.credentials ?? {
          address: vaultAddress,
          token: vaultToken,
        };
        scanParams = formCreds?.scanParams ?? {
          address: vaultAddress,
          include: { kv: includeKV, pki: includePKI },
          pathPrefix: pathPrefix || '',
          maxItemsPerMount: maxItemsPerMount || 1000,
        };
        break;
      }
      case 'aws': {
        const formCreds = awsFormRef.current?.getCredentials();
        if (formCreds) {
          credentials = formCreds.credentials;
          scanParams = formCreds.scanParams;
        } else {
          ({ credentials, scanParams } = buildAwsAutoSyncPayload({
            accessKeyId: awsAccessKeyId,
            secretAccessKey: awsSecretAccessKey,
            awsRegion,
            awsDetectedRegions: _awsDetectedRegions,
          }));
        }
        break;
      }
      case 'azure': {
        const formCreds = azureFormRef.current?.getCredentials();
        credentials = formCreds?.credentials ?? {
          vaultUrl: azureVaultUrl,
          token: azureToken,
        };
        scanParams = formCreds?.scanParams ?? {
          vaultUrl: azureVaultUrl,
          include: { secrets: true, certificates: true, keys: true },
        };
        break;
      }
      case 'azure-ad':
        credentials = { token: azureADToken };
        scanParams = {
          include: {
            applications: azureADIncludeApps,
            servicePrincipals: azureADIncludeSPs,
          },
        };
        break;
      case 'gcp': {
        const formCreds = gcpFormRef.current?.getCredentials();
        credentials = formCreds?.credentials ?? {
          projectId: gcpProjectId,
          accessToken: gcpAccessToken,
        };
        scanParams = formCreds?.scanParams ?? {
          projectId: gcpProjectId,
          include: { secrets: true },
        };
        break;
      }
    }
    return { credentials, scanParams };
  };

  // Enable auto-sync confirmation modal
  const {
    isOpen: isEnableAutoSyncOpen,
    onOpen: onEnableAutoSyncOpen,
    onClose: onEnableAutoSyncClose,
  } = useDisclosure();
  const [enableSyncFrequency, setEnableSyncFrequency] = React.useState('daily');
  const [enableSyncTime, setEnableSyncTime] = React.useState('09:00');
  const [enableSyncTz, setEnableSyncTz] = React.useState(
    Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  );

  React.useEffect(() => {
    if (integrationSubTab === 'manage' && autoSyncConfig?.id) {
      setEnableSyncFrequency(autoSyncConfig.frequency || 'daily');
      setEnableSyncTime(autoSyncConfig.schedule_time || '09:00');
      setEnableSyncTz(
        autoSyncConfig.schedule_tz ||
          Intl.DateTimeFormat().resolvedOptions().timeZone ||
          'UTC'
      );
    }
  }, [integrationSubTab, autoSyncConfig]);

  const credentialsHasSecrets = (credentials, providerName) => {
    if (!credentials || typeof credentials !== 'object') return false;
    switch (providerName) {
      case 'github':
      case 'gitlab':
      case 'vault':
      case 'azure':
      case 'azure-ad':
      case 'gcp':
        return Boolean(String(credentials.token || '').trim());
      case 'aws':
        return Boolean(
          String(
            credentials.secretAccessKey || credentials.secret_access_key || ''
          ).trim()
        );
      default:
        return Object.values(credentials).some(v =>
          Boolean(String(v || '').trim())
        );
    }
  };

  const openEnableAutoSyncModal = () => {
    setEnableSyncFrequency('daily');
    setEnableSyncTime('09:00');
    setEnableSyncTz(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC');
    onEnableAutoSyncOpen();
  };

  const handleEnableAutoSync = () => {
    if (!workspaceId || source === 'file') return;
    openEnableAutoSyncModal();
  };

  const handleSaveAutoSyncChanges = async () => {
    if (!workspaceId || !autoSyncConfig?.id) return;
    const { credentials, scanParams } = getAutoSyncCredentials();
    const payload = {
      frequency: enableSyncFrequency,
      schedule_time: enableSyncTime,
      schedule_tz: enableSyncTz,
    };
    if (credentialsHasSecrets(credentials, source)) {
      payload.credentials = credentials;
      payload.scan_params = scanParams;
    }
    setSavingAutoSync(true);
    try {
      await apiClient.put(
        `/api/v1/workspaces/${workspaceId}/auto-sync/${autoSyncConfig.id}`,
        payload
      );
      const res = await apiClient.get(
        `/api/v1/workspaces/${workspaceId}/auto-sync`
      );
      const configs = res.data?.items || [];
      setAutoSyncConfig(configs.find(c => c.provider === source) || false);
      showSuccess(`Auto-sync settings updated for ${source}`);
    } catch (e) {
      showWarning(
        e?.response?.data?.error || 'Failed to update auto-sync settings'
      );
    } finally {
      setSavingAutoSync(false);
    }
  };

  const handleRunAutoSyncNow = async () => {
    if (!workspaceId || !autoSyncConfig?.id) return;
    const baselineLastSyncAt = autoSyncConfig.last_sync_at || null;
    autoSyncPollCancelRef.current = false;
    setRunningAutoSyncNow(true);
    try {
      await apiClient.post(
        `/api/v1/workspaces/${workspaceId}/auto-sync/${autoSyncConfig.id}/run`
      );
      const outcome = await pollAutoSyncAfterRun({
        workspaceId,
        provider: source,
        baselineLastSyncAt,
        onUpdate: setAutoSyncConfig,
        isCancelled: () => autoSyncPollCancelRef.current,
      });
      if (outcome === 'cancelled') return;
      if (outcome === 'success' || outcome === 'partial') {
        showSuccess(`Auto-sync completed (${outcome})`);
        dispatchNotificationsRefresh();
        return;
      }
      if (outcome === 'failed') {
        const res = await apiClient.get(
          `/api/v1/workspaces/${workspaceId}/auto-sync`
        );
        const cfg =
          (res.data?.items || []).find(c => c.provider === source) || null;
        showWarning(cfg?.last_sync_error || 'Auto-sync failed again');
        dispatchNotificationsRefresh();
        return;
      }
      if (outcome === 'timeout') {
        showSuccess(
          'Sync queued. Status will update when the worker finishes.'
        );
        return;
      }
      showWarning('Auto-sync config is no longer available');
    } catch (e) {
      showWarning(e?.response?.data?.error || 'Failed to queue sync');
    } finally {
      setRunningAutoSyncNow(false);
    }
  };

  const confirmEnableAutoSync = async () => {
    onEnableAutoSyncClose();
    setSavingAutoSync(true);
    try {
      const { credentials, scanParams } = getAutoSyncCredentials();
      await apiClient.post(`/api/v1/workspaces/${workspaceId}/auto-sync`, {
        provider: source,
        credentials,
        scan_params: scanParams,
        frequency: enableSyncFrequency,
        schedule_time: enableSyncTime,
        schedule_tz: enableSyncTz,
      });
      showSuccess(`Auto-sync enabled for ${source}`);
      const res = await apiClient.get(
        `/api/v1/workspaces/${workspaceId}/auto-sync`
      );
      const configs = res.data?.items || [];
      setAutoSyncConfig(configs.find(c => c.provider === source) || false);
      setIntegrationSubTab('manage');
    } catch (e) {
      showWarning(e?.response?.data?.error || 'Failed to enable auto-sync');
    } finally {
      setSavingAutoSync(false);
    }
  };

  // Disable auto-sync confirmation modal
  const {
    isOpen: isDisableAutoSyncOpen,
    onOpen: onDisableAutoSyncOpen,
    onClose: onDisableAutoSyncClose,
  } = useDisclosure();

  const handleDisableAutoSync = () => {
    if (!workspaceId || !autoSyncConfig?.id) return;
    onDisableAutoSyncOpen();
  };

  const confirmDisableAutoSync = async () => {
    onDisableAutoSyncClose();
    setSavingAutoSync(true);
    try {
      await apiClient.delete(
        `/api/v1/workspaces/${workspaceId}/auto-sync/${autoSyncConfig.id}`
      );
      setAutoSyncConfig(false);
      setIntegrationSubTab('scan');
      setPendingManageTab(false);
      showSuccess(`Auto-sync disabled for ${source}`);
      dispatchNotificationsRefresh();
    } catch (e) {
      showWarning(e?.response?.data?.error || 'Failed to disable auto-sync');
    } finally {
      setSavingAutoSync(false);
    }
  };

  // Selected count for integration forms (reported by onSelectionChange)
  const [integrationSelectedCount, setIntegrationSelectedCount] =
    React.useState(0);

  // Reset bulk section and integration count when source changes
  React.useEffect(() => {
    setBulkSection('');
    setBulkContactGroupId('');
    setIntegrationSelectedCount(0);
  }, [source]);

  // Note: We no longer pre-fill bulkSection with generic integration names
  // This allows tokens to keep their granular source-based sections
  // (e.g., "gitlab-pat", "gitlab-project-token", "github-ssh-key", "aws-iam-key")
  // Users can still manually set a bulk section to override all selected tokens

  const reset = React.useCallback(() => {
    setSource('file');
    setFile(null);
    setRows([]);
    setParsing(false);
    setError(null);
    setFailedRows([]);
    setIsImporting(false);
    setProgress({ done: 0, total: 0 });
    abortRef.current = null;
    // Reset bulk assignment state
    setBulkSection('');
    setBulkContactGroupId('');
    // Reset vault state
    setVaultAddress('');
    setVaultToken('');
    setIncludeKV(true);
    setIncludePKI(true);
    setIsScanning(false);
    setScanSucceededFor(new Set());
    setMounts([]);
    setVaultItems([]);
    setSummary([]);
    setVaultDefaults({
      category: 'general',
      type: 'other',
      contact_group_id: '',
    });
    // Reset all selection states
    setSelectedRowsFile(new Set());
    setSelectedRowsVault(new Set());
    setSelectedRowsGitlab(new Set());
    setSelectedRowsGithub(new Set());
    setSelectedRowsAws(new Set());
    setSelectedRowsAzure(new Set());
    setSelectedRowsGcp(new Set());
    setSelectedRowsAzureAD(new Set());
    // Reset duplicate detection state
    setFileDuplicates(new Set());
    setVaultDuplicates(new Set());
    setGitlabDuplicates(new Set());
    setGithubDuplicates(new Set());
    setAwsDuplicates(new Set());
    setAzureDuplicates(new Set());
    setGcpDuplicates(new Set());
    setAzureADDuplicates(new Set());
    setIntegrationSubTab('scan');
    setPendingManageTab(false);
  }, []);

  const onSelectFile = async e => {
    const f = e?.target?.files?.[0];
    setError(null);
    setRows([]);
    setSelectedRowsFile(new Set());
    setFileDuplicates(new Set());
    if (!f) return;
    setFile(f);
    try {
      setFileName(f.name || '');
    } catch (_) {
      setFileName('');
    }
    setParsing(true);
    try {
      const parsed = await parseFile(f);
      const normalized = (parsed || [])
        .map(normalizeRow)
        .filter(r => r && r.name && r.category && r.type && r.expiresAt);
      setRows(normalized);
      // Auto-select all rows
      setSelectedRowsFile(new Set(normalized.map((_, i) => i)));

      // Check for duplicates after parsing
      const params = new URLSearchParams(window.location.search);
      const workspaceId = params.get('workspace');
      if (workspaceId && normalized.length > 0) {
        try {
          const items = normalized.map(r => ({
            name: r.name,
            location: r.location || null,
          }));
          const duplicateCheck = await integrationAPI.checkDuplicates({
            workspaceId,
            items,
          });
          if (duplicateCheck.duplicate_count > 0) {
            // Build a set of indices that are duplicates
            const duplicateSet = new Set();
            duplicateCheck.duplicates.forEach(dup => {
              // Find matching row by name and location
              normalized.forEach((row, idx) => {
                if (
                  row.name === dup.name &&
                  (row.location || null) === (dup.location || null)
                ) {
                  duplicateSet.add(idx);
                }
              });
            });
            setFileDuplicates(duplicateSet);
          }
        } catch (_) {
          // Silently ignore duplicate check errors
        }
      }
    } catch (err) {
      setError(err?.message || 'Failed to parse file');
    } finally {
      setParsing(false);
    }
  };

  const onStartImport = async () => {
    if (source !== 'file') return; // handled by vault import flow
    try {
      setError(null);
      setIsImporting(true);
      const selectedRows = rows.filter((_, i) => selectedRowsFile.has(i));
      setProgress({ done: 0, total: selectedRows.length });
      const params = new URLSearchParams(window.location.search);
      const workspaceId = params.get('workspace');
      if (!workspaceId) {
        setError('Please select a workspace first.');
        setIsImporting(false);
        return;
      }
      const controller = new AbortController();
      abortRef.current = controller;
      // Resolve default contact group id for workspace (if any)
      let defaultGroupId = null;
      try {
        const alertSettings = await workspaceAPI.getAlertSettings(workspaceId);
        if (alertSettings && alertSettings.default_contact_group_id) {
          defaultGroupId = String(alertSettings.default_contact_group_id);
        }
      } catch (_) {}
      const { created, updated, errors } = await importWithConcurrency(
        selectedRows,
        workspaceId,
        setProgress,
        controller.signal,
        4,
        defaultGroupId
      );
      if (errors.length > 0) {
        // Keep a sanitized, concise preview of errors
        const safeErrors = errors.map(e => ({
          index: e.index,
          error: String(e.error || 'Unknown error').slice(0, 200),
        }));
        setFailedRows(safeErrors);
        if (updated && updated.length > 0) {
          setError(
            `Imported ${created.length} new items, updated ${updated.length} existing items, with ${errors.length} errors.`
          );
        } else {
          setError(`Imported ${created.length} with ${errors.length} errors.`);
        }
      } else if (updated && updated.length > 0) {
        // No errors, but some were updated
        setError(null); // Clear any previous errors
        // Show success message via the onImported callback or a success notification
      }
      if (created.length > 0 || (updated && updated.length > 0)) {
        onImported && onImported([...created, ...(updated || [])]);
      }
    } catch (e) {
      setError(e?.message || 'Import failed');
    } finally {
      setIsImporting(false);
    }
  };

  const onCancelImport = () => {
    try {
      abortRef.current && abortRef.current.abort();
    } catch (_) {}
    setIsImporting(false);
  };

  const onCloseInternal = () => {
    try {
      reset();
    } catch (err) {
      logger.error('[ImportModal] Reset failed during close', err);
    } finally {
      try {
        onEnableAutoSyncClose();
      } catch (_) {}
      try {
        onDisableAutoSyncClose();
      } catch (_) {}
      onClose && onClose();
    }
  };

  // Update quota from scan response
  const updateQuotaFromResponse = res => {
    if (res?.quota) {
      const { used, limit, remaining } = res.quota;
      logger.info('[UpdateQuota from response]', { used, limit, remaining });
      const newQuota = {
        used: typeof used === 'number' ? used : 0,
        limit,
        remaining:
          typeof remaining === 'number'
            ? remaining
            : limit !== null
              ? Math.max(0, limit - used)
              : null,
      };
      logger.info('[UpdateQuota] Setting new quota state:', newQuota);
      setIntegrationQuota(newQuota);
      return true;
    }
    logger.warn('[UpdateQuota] No quota in response, will refresh from API');
    return false;
  };

  // Refresh integration quota after a scan (fallback if response doesn't include quota)
  const refreshIntegrationQuota = async () => {
    const workspaceId = getWorkspaceId();
    if (!workspaceId) return;

    try {
      // No delay needed - database function is atomic and immediately consistent
      const planInfo = await authAPI.getPlan(workspaceId);
      logger.info('[RefreshQuota from API]', {
        used: planInfo.integrationScansUsed,
        limit: planInfo.integrationScansLimit,
        remaining: planInfo.integrationScansRemaining,
      });
      const used =
        typeof planInfo.integrationScansUsed === 'number'
          ? planInfo.integrationScansUsed
          : 0;
      const limit = planInfo.integrationScansLimit; // null for unlimited
      const remaining =
        typeof planInfo.integrationScansRemaining === 'number'
          ? planInfo.integrationScansRemaining
          : limit !== null
            ? Math.max(0, limit - used)
            : null;

      logger.info('[RefreshQuota] Setting quota state:', {
        used,
        limit,
        remaining,
      });
      setIntegrationQuota({ used, limit, remaining });
    } catch (err) {
      logger.error('[RefreshQuota] Failed:', err);
      // If refresh fails, show error to user (visible even in production)
      logger.error(
        'Failed to refresh integration quota. Please refresh the page.',
        err
      );
      // Try to force a re-render by setting to the same state (will trigger key change)
      setIntegrationQuota(prev => ({ ...prev }));
    }
  };

  // Handle quota exceeded error
  const isQuotaExceededError = error => {
    const errorCode = error?.code || error?.response?.data?.code;
    return errorCode === 'INTEGRATION_QUOTA_EXCEEDED';
  };

  const formatQuotaError = error => {
    const quota = error?.quota || error?.response?.data?.quota;
    if (quota) {
      // Update the quota state from the error response (most accurate data)
      setIntegrationQuota({
        used: quota.used,
        limit: quota.limit,
        remaining: quota.remaining,
      });
      const resetDate = quota.resetsAt
        ? new Date(quota.resetsAt).toLocaleDateString()
        : 'next month';
      return `Monthly scan limit reached (${quota.used}/${quota.limit}). Resets on ${resetDate}.`;
    }
    return error?.message || 'Integration scan limit reached.';
  };

  // Extract quota from any error response (not just quota-exceeded errors)
  const extractQuotaFromError = error => {
    const quota = error?.quota || error?.response?.data?.quota;
    if (quota && typeof quota.used === 'number') {
      logger.info('[ExtractQuota from error]', quota);
      setIntegrationQuota({
        used: quota.used,
        limit: quota.limit,
        remaining: quota.remaining,
      });
      return true; // Quota was extracted
    }
    return false; // No quota in error response
  };

  // Helper to get workspaceId from URL params
  const getWorkspaceId = () => {
    const params = new URLSearchParams(window.location.search);
    return params.get('workspace');
  };

  const updateAzureADItem = (index, updates) => {
    setAzureADItems(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], ...updates };
      return updated;
    });
  };

  // Azure AD scan and import
  const doAzureADScan = async () => {
    const workspaceId = getWorkspaceId();
    if (!workspaceId) {
      setError('Please select a workspace first.');
      return;
    }

    // Validate required fields BEFORE calling API to avoid consuming quota
    if (!azureADToken || !azureADToken.trim()) {
      setError('Azure AD access token is required');
      return;
    }

    setError(null);
    setIsScanning(true);
    setAzureADItems([]);
    setAzureADSummary([]);
    try {
      const res = await azureADAPI.scan({
        workspaceId,
        token: azureADToken,
        include: {
          applications: azureADIncludeApps,
          servicePrincipals: azureADIncludeSPs,
        },
        maxItems: 2000,
      });
      const items = Array.isArray(res?.items) ? res.items : [];
      setAzureADItems(items);
      setAzureADSummary(Array.isArray(res?.summary) ? res.summary : []);
      if (items.length > 0)
        setScanSucceededFor(prev => new Set(prev).add('azure-ad'));

      // Update quota from response (if available) or refresh from API
      if (!updateQuotaFromResponse(res)) {
        await refreshIntegrationQuota();
      }

      // Check for duplicates
      const dups = await checkDuplicatesForItems(items, workspaceId);
      setAzureADDuplicates(dups);
    } catch (e) {
      // Clear summary on error to prevent showing partial/error data
      setAzureADItems([]);
      setAzureADSummary([]);
      // Handle quota exceeded error
      if (isQuotaExceededError(e)) {
        setError(formatQuotaError(e));
      } else {
        setError(e?.message || 'Azure AD scan failed');
      }
      // Extract quota from error response, or refresh if not present
      if (!extractQuotaFromError(e)) {
        await refreshIntegrationQuota();
      }
    } finally {
      setIsScanning(false);
    }
  };

  const importAzureADSelected = async () => {
    try {
      setIsImporting(true);
      const selected = azureADItems
        .filter((_, i) => selectedRowsAzureAD.has(i))
        .map(item => ({
          ...item,
          section: bulkSection || item.section || null,
          contact_group_id: bulkContactGroupId || null,
        }));
      const params = new URLSearchParams(window.location.search);
      const workspaceId = params.get('workspace');
      if (!workspaceId) {
        setError('Please select a workspace first.');
        setIsImporting(false);
        return;
      }

      await integrationAPI.import({
        workspaceId,
        items: selected,
        defaults: {},
      });
      onImported && onImported(selected);
    } catch (e) {
      setError(e?.message || 'Azure AD import failed');
    } finally {
      setIsImporting(false);
    }
  };

  // Check if workspace has a paid plan, user role, integration quota, and load contact groups
  React.useEffect(() => {
    logger.info('[ImportModal] useEffect triggered, isOpen:', isOpen);
    if (!isOpen) return;
    const params = new URLSearchParams(window.location.search);
    const workspaceId = params.get('workspace');
    logger.info('[ImportModal] Workspace ID from URL:', workspaceId);
    if (!workspaceId) {
      setIsViewer(false);
      setContactGroups([]);
      setIntegrationQuota({ used: 0, limit: null, remaining: null });
      return;
    }

    (async () => {
      logger.info(
        '[ImportModal] Starting async data fetch for workspace:',
        workspaceId
      );
      try {
        const ws = await workspaceAPI.get(workspaceId);
        logger.info('[ImportModal] Workspace fetched:', ws);
        const plan = String(ws?.plan || 'oss').toLowerCase();
        const role = String(ws?.role || '').toLowerCase();
        logger.info('[ImportModal] Plan:', plan, 'Role:', role);
        setIsViewer(role === 'viewer');

        // Set initial quota based on plan to avoid flash
        if (plan === 'pro' || plan === 'team') {
          setIntegrationQuota({ used: 0, limit: null, remaining: null });
        } else {
          setIntegrationQuota({ used: 0, limit: 3, remaining: 3 });
        }

        // Fetch account plan info for integration quota (per workspace)
        logger.info(
          '[ImportModal] About to fetch quota for workspace:',
          workspaceId
        );
        try {
          const planInfo = await authAPI.getPlan(workspaceId);
          logger.info('[ImportModal] Quota loaded from API:', {
            workspaceId,
            plan,
            used: planInfo.integrationScansUsed,
            limit: planInfo.integrationScansLimit,
            remaining: planInfo.integrationScansRemaining,
          });
          const used =
            typeof planInfo.integrationScansUsed === 'number'
              ? planInfo.integrationScansUsed
              : 0;
          const limit = planInfo.integrationScansLimit; // null for unlimited
          const remaining =
            typeof planInfo.integrationScansRemaining === 'number'
              ? planInfo.integrationScansRemaining
              : limit !== null
                ? Math.max(0, limit - used)
                : null;
          logger.info('[ImportModal] Setting quota state:', {
            used,
            limit,
            remaining,
          });
          setIntegrationQuota({ used, limit, remaining });
        } catch (err) {
          logger.error('[ImportModal] Failed to fetch quota:', err);
          logger.info('[ImportModal] Using default (unlimited)');
          setIntegrationQuota({ used: 0, limit: null, remaining: null });
        }

        // Load contact groups for this workspace
        try {
          const alertSettings =
            await workspaceAPI.getAlertSettings(workspaceId);
          const groups = Array.isArray(alertSettings?.contact_groups)
            ? alertSettings.contact_groups
            : [];
          setContactGroups(groups);
        } catch (_) {
          setContactGroups([]);
        }
      } catch (err) {
        logger.error('[ImportModal] Failed to fetch workspace info:', err);
        setIsViewer(false);
        setContactGroups([]);
        // Try to get quota directly even if workspace fetch failed
        try {
          const planInfo = await authAPI.getPlan(workspaceId);
          const used =
            typeof planInfo.integrationScansUsed === 'number'
              ? planInfo.integrationScansUsed
              : 0;
          const limit = planInfo.integrationScansLimit;
          const remaining =
            typeof planInfo.integrationScansRemaining === 'number'
              ? planInfo.integrationScansRemaining
              : limit !== null
                ? Math.max(0, limit - used)
                : null;
          logger.info('[ImportModal] Quota loaded despite workspace error:', {
            used,
            limit,
            remaining,
          });
          setIntegrationQuota({ used, limit, remaining });
        } catch {
          logger.info(
            '[ImportModal] Complete failure, using unlimited default'
          );
          setIntegrationQuota({ used: 0, limit: null, remaining: null });
        }
      }
    })();
  }, [isOpen]);

  return (
    <>
      <Modal
        isOpen={isOpen}
        onClose={onCloseInternal}
        size='4xl'
        isCentered
        motionPreset='none'
        scrollBehavior='inside'
      >
        <ModalOverlay {...overlayProps} />
        <DashboardModalFrame maxW='960px'>
          <ModalHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Import tokens
            </DashboardModalTitle>
            <DashboardModalDescription>
              Import assets from files or connected infrastructure providers.
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton {...closeButtonProps} />
          <ModalBody {...bodyProps}>
            <VStack align='stretch' spacing={4}>
              {/* Source selector */}
              <Box>
                <Box
                  display='grid'
                  gridTemplateColumns={{
                    base: '1fr',
                    sm: '1fr 1fr',
                    md: 'repeat(4, 1fr)',
                  }}
                  gap={4}
                >
                  {[
                    {
                      key: 'file',
                      label: 'File',
                      alt: 'File import',
                      type: 'icon',
                    },
                    {
                      key: 'vault',
                      label: 'HashiCorp Vault',
                      alt: 'HashiCorp Vault',
                      src: '/Branding/vendor-logos/hashicorp.png',
                    },
                    {
                      key: 'gitlab',
                      label: 'GitLab',
                      alt: 'GitLab',
                      src: '/Branding/vendor-logos/gitlab.png',
                    },
                    {
                      key: 'github',
                      label: 'GitHub',
                      alt: 'GitHub',
                      src: '/Branding/vendor-logos/github.png',
                    },
                    {
                      key: 'aws',
                      label: 'AWS',
                      alt: 'AWS',
                      src: '/Branding/vendor-logos/aws.png',
                    },
                    {
                      key: 'azure',
                      label: 'Azure KV',
                      alt: 'Azure Key Vault',
                      src: '/Branding/vendor-logos/azure.svg',
                    },
                    {
                      key: 'azure-ad',
                      label: 'Azure AD',
                      alt: 'Azure Active Directory',
                      src: '/Branding/vendor-logos/azure.svg',
                    },
                    {
                      key: 'gcp',
                      label: 'GCP',
                      alt: 'Google Cloud',
                      src: '/Branding/vendor-logos/google-cloud-icon.png',
                    },
                  ].map(card => {
                    const isIntegration = card.key !== 'file';
                    const hasQuotaRemaining =
                      integrationQuota.remaining === null ||
                      integrationQuota.remaining > 0;
                    const isLocked =
                      isIntegration && (isViewer || !hasQuotaRemaining);
                    const lockReason = isIntegration
                      ? isViewer
                        ? 'Viewers cannot use integrations'
                        : integrationQuota.remaining === 0
                          ? `Monthly scan limit reached (${integrationQuota.limit}/month).`
                          : ''
                      : '';
                    const selectCard = () => {
                      if (!isLocked) setSource(card.key);
                    };

                    const cardContent = (
                      <VStack
                        spacing={2}
                        align='center'
                        justify='center'
                        p={3}
                        minH={{ base: '116px', md: '132px' }}
                        w='100%'
                        bg={modalTokens.fieldBg}
                        border='1px solid'
                        borderColor={
                          source === card.key
                            ? modalTokens.focusBorder
                            : modalTokens.border
                        }
                        borderRadius='12px'
                        boxShadow={
                          source === card.key
                            ? '0 0 0 1px rgba(59, 130, 246, 0.35)'
                            : 'none'
                        }
                        cursor={isLocked ? 'not-allowed' : 'pointer'}
                        opacity={isLocked ? 0.6 : 1}
                        onClick={selectCard}
                        onKeyDown={e => {
                          if (
                            !isLocked &&
                            (e.key === 'Enter' || e.key === ' ')
                          ) {
                            e.preventDefault();
                            selectCard();
                          }
                        }}
                        tabIndex={isLocked ? -1 : 0}
                        role='button'
                        aria-label={card.alt}
                        aria-disabled={isLocked}
                        aria-pressed={source === card.key}
                        transition='border-color 0.15s ease, box-shadow 0.15s ease'
                        _hover={
                          isLocked
                            ? undefined
                            : {
                                borderColor: modalTokens.focusBorder,
                                bg: modalTokens.fieldBg,
                              }
                        }
                        _focusVisible={{
                          outline: '2px solid',
                          outlineColor: modalTokens.focusBorder,
                          outlineOffset: '2px',
                        }}
                      >
                        <HStack spacing={1}>
                          <Text
                            fontSize='sm'
                            fontWeight='semibold'
                            color={modalTokens.text}
                          >
                            {card.label}
                          </Text>
                          {isLocked && (
                            <Badge colorScheme='orange' fontSize='2xs'>
                              {isViewer ? 'ADMIN' : 'LIMIT'}
                            </Badge>
                          )}
                        </HStack>
                        {card.type === 'icon' ? (
                          <Box p={2}>
                            <Box
                              as={FiDownload}
                              boxSize={{ base: '40px', md: '56px' }}
                              color={
                                source === card.key
                                  ? modalTokens.focusBorder
                                  : modalTokens.muted
                              }
                            />
                          </Box>
                        ) : (
                          <Box position='relative'>
                            <Image
                              src={card.src}
                              alt=''
                              aria-hidden
                              maxH={{ base: '56px', md: '72px' }}
                              maxW='100%'
                              objectFit='contain'
                              opacity={isLocked ? 0.4 : 1}
                              filter={isLocked ? 'grayscale(100%)' : 'none'}
                            />
                            {/* Icon badge to differentiate Azure services */}
                            {card.key === 'azure' && (
                              <Tooltip label='Azure Key Vault' fontSize='xs'>
                                <Box
                                  position='absolute'
                                  top='-6px'
                                  right='-6px'
                                  bg='blue.500'
                                  borderRadius='full'
                                  p={1.5}
                                  boxShadow='md'
                                  border='2px solid white'
                                >
                                  <Box
                                    as={FiKey}
                                    boxSize='14px'
                                    color='white'
                                  />
                                </Box>
                              </Tooltip>
                            )}
                            {card.key === 'azure-ad' && (
                              <Tooltip
                                label='Azure Active Directory'
                                fontSize='xs'
                              >
                                <Box
                                  position='absolute'
                                  top='-6px'
                                  right='-6px'
                                  bg='purple.500'
                                  borderRadius='full'
                                  p={1.5}
                                  boxShadow='md'
                                  border='2px solid white'
                                >
                                  <Box
                                    as={FiUsers}
                                    boxSize='14px'
                                    color='white'
                                  />
                                </Box>
                              </Tooltip>
                            )}
                          </Box>
                        )}
                      </VStack>
                    );

                    return (
                      <Tooltip
                        key={card.key}
                        label={lockReason}
                        fontSize='xs'
                        isDisabled={!isLocked || !lockReason}
                      >
                        {cardContent}
                      </Tooltip>
                    );
                  })}
                </Box>
              </Box>

              {source !== 'file' && hasAutoSync && !isViewer ? (
                <ButtonGroup size='sm' isAttached variant='outline'>
                  <Button
                    colorScheme={
                      integrationSubTab === 'scan' ? 'blue' : undefined
                    }
                    variant={integrationSubTab === 'scan' ? 'solid' : 'outline'}
                    onClick={() => setIntegrationSubTab('scan')}
                  >
                    Scan & Import
                  </Button>
                  <Button
                    colorScheme={
                      integrationSubTab === 'manage' ? 'blue' : undefined
                    }
                    variant={
                      integrationSubTab === 'manage' ? 'solid' : 'outline'
                    }
                    onClick={() => setIntegrationSubTab('manage')}
                  >
                    Manage auto-sync
                  </Button>
                </ButtonGroup>
              ) : null}

              {autoSyncManageMode ? (
                <Box
                  border='1px solid'
                  borderColor={border}
                  borderRadius='md'
                  p={4}
                >
                  <VStack align='stretch' spacing={4}>
                    {autoSyncConfig.last_sync_status === 'failed' ? (
                      <Alert status='error' borderRadius='md'>
                        <AlertIcon />
                        <Box fontSize='sm'>
                          <Text fontWeight='semibold'>
                            Last auto-sync failed
                          </Text>
                          {autoSyncConfig.last_sync_error ? (
                            <Text mt={1}>{autoSyncConfig.last_sync_error}</Text>
                          ) : null}
                        </Box>
                      </Alert>
                    ) : null}
                    <Box>
                      <Text fontSize='sm' fontWeight='semibold' mb={2}>
                        Status
                      </Text>
                      <Text fontSize='sm'>
                        Provider: {autoSyncConfig.provider}
                      </Text>
                      {autoSyncConfig.last_sync_at ? (
                        <Text fontSize='sm'>
                          Last sync:{' '}
                          {new Date(
                            autoSyncConfig.last_sync_at
                          ).toLocaleString()}
                          {autoSyncConfig.last_sync_status
                            ? ` (${autoSyncConfig.last_sync_status})`
                            : ''}
                        </Text>
                      ) : (
                        <Text fontSize='sm' color={muted}>
                          No sync run yet
                        </Text>
                      )}
                    </Box>
                    <Divider />
                    <Box>
                      <Text fontSize='sm' fontWeight='semibold' mb={3}>
                        Schedule
                      </Text>
                      <VStack align='stretch' spacing={3}>
                        <HStack spacing={4} align='flex-end' flexWrap='wrap'>
                          <FormControl flex='1' minW='140px'>
                            <FormLabel fontSize='sm'>Frequency</FormLabel>
                            <Select
                              size='sm'
                              value={enableSyncFrequency}
                              onChange={e =>
                                setEnableSyncFrequency(e.target.value)
                              }
                            >
                              <option value='daily'>Daily</option>
                              <option value='weekly'>Weekly</option>
                              <option value='monthly'>Monthly</option>
                            </Select>
                          </FormControl>
                          <FormControl flex='1' minW='140px'>
                            <FormLabel fontSize='sm'>Time</FormLabel>
                            <Input
                              size='sm'
                              type='time'
                              value={enableSyncTime}
                              onChange={e => setEnableSyncTime(e.target.value)}
                            />
                          </FormControl>
                        </HStack>
                        <FormControl>
                          <FormLabel fontSize='sm'>Timezone</FormLabel>
                          <Select
                            size='sm'
                            value={enableSyncTz}
                            onChange={e => setEnableSyncTz(e.target.value)}
                          >
                            {timezoneList.map(tz => (
                              <option key={tz} value={tz}>
                                {tz.replace(/_/g, ' ')}
                              </option>
                            ))}
                          </Select>
                        </FormControl>
                      </VStack>
                    </Box>
                    <Divider />
                    <Box>
                      <Text fontSize='sm' fontWeight='semibold' mb={1}>
                        Credentials
                      </Text>
                      <Text fontSize='sm' color={muted}>
                        Enter a new token or API key to rotate stored
                        credentials. Leave blank to keep the current secret.
                      </Text>
                    </Box>
                  </VStack>
                </Box>
              ) : null}

              {source === 'file' ? (
                <>
                  <Box>
                    <Text fontSize='sm' color={muted}>
                      Upload a file in .csv, .xlsx, .json, .yaml or .yml format.
                      Required fields per row: name, category, type, expiresAt.
                    </Text>
                    <Text fontSize='sm' mt={1}>
                      <ChakraLink
                        onClick={() =>
                          window.open(
                            'https://tokentimer.ch/docs/tokens#import-file',
                            '_blank',
                            'noopener,noreferrer'
                          )
                        }
                        cursor='pointer'
                        color='blue.500'
                        textDecoration='underline'
                        isExternal
                      >
                        Learn more about importing from files →
                      </ChakraLink>
                    </Text>
                  </Box>
                  <Input
                    ref={fileInputRef}
                    type='file'
                    accept='.csv,.xlsx,.xls,.json,.yaml,.yml'
                    onChange={onSelectFile}
                    isDisabled={parsing || isImporting}
                    display='none'
                  />
                  <HStack justify='flex-start' spacing={3}>
                    <Button
                      onClick={() => fileInputRef.current?.click()}
                      isDisabled={parsing || isImporting}
                    >
                      Choose file
                    </Button>
                    <Text fontSize='sm' color={muted}>
                      {fileName ? fileName : 'No file chosen'}
                    </Text>
                  </HStack>
                </>
              ) : null}

              {source === 'vault' && !autoSyncManageMode ? (
                <ImportVaultForm
                  ref={vaultFormRef}
                  workspaceId={workspaceId}
                  onImportComplete={selected => {
                    setIsImporting(false);
                    onImported && onImported(selected);
                  }}
                  onError={err => {
                    setError(err);
                    setIsImporting(false);
                  }}
                  onScanSuccess={s =>
                    setScanSucceededFor(prev => new Set(prev).add(s))
                  }
                  onSelectionChange={setIntegrationSelectedCount}
                  borderColor={border}
                  helpTextColor={muted}
                  autoSyncTokenPlaceholder={autoSyncTokenPlaceholder}
                  updateQuotaFromResponse={updateQuotaFromResponse}
                  refreshIntegrationQuota={refreshIntegrationQuota}
                  isQuotaExceededError={isQuotaExceededError}
                  formatQuotaError={formatQuotaError}
                  extractQuotaFromError={extractQuotaFromError}
                  contactGroups={contactGroups}
                />
              ) : null}

              {source === 'gitlab' ? (
                <ImportGitLabForm
                  ref={gitlabFormRef}
                  workspaceId={workspaceId}
                  onImportComplete={selected => {
                    setIsImporting(false);
                    onImported && onImported(selected);
                  }}
                  onError={err => {
                    setError(err);
                    setIsImporting(false);
                  }}
                  onScanSuccess={s =>
                    setScanSucceededFor(prev => new Set(prev).add(s))
                  }
                  onSelectionChange={setIntegrationSelectedCount}
                  borderColor={border}
                  helpTextColor={muted}
                  autoSyncTokenPlaceholder={autoSyncTokenPlaceholder}
                  updateQuotaFromResponse={updateQuotaFromResponse}
                  refreshIntegrationQuota={refreshIntegrationQuota}
                  isQuotaExceededError={isQuotaExceededError}
                  formatQuotaError={formatQuotaError}
                  extractQuotaFromError={extractQuotaFromError}
                  autoSyncManageMode={autoSyncManageMode}
                  contactGroups={contactGroups}
                />
              ) : null}

              {source === 'github' ? (
                <ImportGitHubForm
                  ref={githubFormRef}
                  workspaceId={workspaceId}
                  onImportComplete={selected => {
                    setIsImporting(false);
                    onImported && onImported(selected);
                  }}
                  onError={err => {
                    setError(err);
                    setIsImporting(false);
                  }}
                  onScanSuccess={s =>
                    setScanSucceededFor(prev => new Set(prev).add(s))
                  }
                  onSelectionChange={setIntegrationSelectedCount}
                  borderColor={border}
                  helpTextColor={muted}
                  autoSyncTokenPlaceholder={autoSyncTokenPlaceholder}
                  autoSyncManageMode={autoSyncManageMode}
                  updateQuotaFromResponse={updateQuotaFromResponse}
                  refreshIntegrationQuota={refreshIntegrationQuota}
                  isQuotaExceededError={isQuotaExceededError}
                  formatQuotaError={formatQuotaError}
                  extractQuotaFromError={extractQuotaFromError}
                  contactGroups={contactGroups}
                />
              ) : null}

              {source === 'aws' && !autoSyncManageMode ? (
                <ImportAWSForm
                  ref={awsFormRef}
                  initialAutoSyncScanParams={awsAutoSyncScanParams}
                  workspaceId={workspaceId}
                  onImportComplete={selected => {
                    setIsImporting(false);
                    onImported && onImported(selected);
                  }}
                  onError={err => {
                    setError(err);
                    setIsImporting(false);
                  }}
                  onScanSuccess={s =>
                    setScanSucceededFor(prev => new Set(prev).add(s))
                  }
                  onSelectionChange={setIntegrationSelectedCount}
                  borderColor={border}
                  helpTextColor={muted}
                  autoSyncTokenPlaceholder={autoSyncTokenPlaceholder}
                  updateQuotaFromResponse={updateQuotaFromResponse}
                  refreshIntegrationQuota={refreshIntegrationQuota}
                  isQuotaExceededError={isQuotaExceededError}
                  formatQuotaError={formatQuotaError}
                  extractQuotaFromError={extractQuotaFromError}
                  contactGroups={contactGroups}
                />
              ) : null}

              {source === 'azure' && !autoSyncManageMode ? (
                <ImportAzureForm
                  ref={azureFormRef}
                  workspaceId={workspaceId}
                  onImportComplete={selected => {
                    setIsImporting(false);
                    onImported && onImported(selected);
                  }}
                  onError={err => {
                    setError(err);
                    setIsImporting(false);
                  }}
                  onScanSuccess={s =>
                    setScanSucceededFor(prev => new Set(prev).add(s))
                  }
                  onSelectionChange={setIntegrationSelectedCount}
                  borderColor={border}
                  helpTextColor={muted}
                  autoSyncTokenPlaceholder={autoSyncTokenPlaceholder}
                  updateQuotaFromResponse={updateQuotaFromResponse}
                  refreshIntegrationQuota={refreshIntegrationQuota}
                  isQuotaExceededError={isQuotaExceededError}
                  formatQuotaError={formatQuotaError}
                  extractQuotaFromError={extractQuotaFromError}
                  contactGroups={contactGroups}
                />
              ) : null}

              {source === 'gcp' && !autoSyncManageMode ? (
                <ImportGCPForm
                  ref={gcpFormRef}
                  workspaceId={workspaceId}
                  onImportComplete={selected => {
                    setIsImporting(false);
                    onImported && onImported(selected);
                  }}
                  onError={err => {
                    setError(err);
                    setIsImporting(false);
                  }}
                  onScanSuccess={s =>
                    setScanSucceededFor(prev => new Set(prev).add(s))
                  }
                  onSelectionChange={setIntegrationSelectedCount}
                  borderColor={border}
                  helpTextColor={muted}
                  autoSyncTokenPlaceholder={autoSyncTokenPlaceholder}
                  updateQuotaFromResponse={updateQuotaFromResponse}
                  refreshIntegrationQuota={refreshIntegrationQuota}
                  isQuotaExceededError={isQuotaExceededError}
                  formatQuotaError={formatQuotaError}
                  extractQuotaFromError={extractQuotaFromError}
                  contactGroups={contactGroups}
                />
              ) : null}

              {source === 'azure-ad' && !autoSyncManageMode ? (
                <VStack align='stretch' spacing={3}>
                  <Box>
                    <Text fontSize='sm' color={muted}>
                      Scans Azure AD for app registrations and service
                      principals with expiring client secrets and certificates.
                      Token is used for scanning and stored encrypted if
                      auto-sync is enabled.
                    </Text>
                    <Text fontSize='sm' mt={1}>
                      <ChakraLink
                        onClick={() =>
                          window.open(
                            'https://tokentimer.ch/docs/tokens#import-azure-ad',
                            '_blank',
                            'noopener,noreferrer'
                          )
                        }
                        cursor='pointer'
                        color='blue.500'
                        textDecoration='underline'
                        isExternal
                      >
                        Learn more about importing from Azure AD →
                      </ChakraLink>
                    </Text>
                  </Box>
                  <HStack spacing={3} align='flex-start' flexWrap='wrap'>
                    <Box minW='380px'>
                      <Text fontSize='sm' mb={1}>
                        Microsoft Graph API Token
                      </Text>
                      <InputGroup>
                        <Input
                          type={showSecrets.azureAD ? 'text' : 'password'}
                          placeholder={
                            autoSyncTokenPlaceholder ||
                            'Paste access token with Application.Read.All permission'
                          }
                          value={azureADToken}
                          onChange={e => setAzureADToken(e.target.value)}
                        />
                        <InputRightElement>
                          <IconButton
                            size='xs'
                            variant='ghost'
                            icon={
                              showSecrets.azureAD ? <FiEyeOff /> : <FiEye />
                            }
                            onClick={() => toggleSecret('azureAD')}
                            aria-label={showSecrets.azureAD ? 'Hide' : 'Show'}
                          />
                        </InputRightElement>
                      </InputGroup>
                      <Text fontSize='xs' color={muted} mt={1}>
                        Get token:{' '}
                        <Code fontSize='xs'>
                          az account get-access-token --resource
                          https://graph.microsoft.com
                        </Code>
                      </Text>
                    </Box>
                    <VStack align='start' spacing={2} mt={6}>
                      <HStack>
                        <Switch
                          isChecked={azureADIncludeApps}
                          onChange={e =>
                            setAzureADIncludeApps(e.target.checked)
                          }
                          colorScheme='blue'
                        />
                        <Text fontSize='sm'>Scan App Registrations</Text>
                      </HStack>
                      <HStack>
                        <Switch
                          isChecked={azureADIncludeSPs}
                          onChange={e => setAzureADIncludeSPs(e.target.checked)}
                          colorScheme='blue'
                        />
                        <Text fontSize='sm'>Scan Service Principals</Text>
                      </HStack>
                    </VStack>
                    <Button
                      colorScheme='blue'
                      onClick={doAzureADScan}
                      isLoading={isScanning}
                      alignSelf='flex-end'
                    >
                      Scan
                    </Button>
                  </HStack>
                  {azureADSummary.length > 0 && !error && (
                    <Box
                      border='1px solid'
                      borderColor={border}
                      borderRadius='md'
                      p={3}
                    >
                      <VStack align='stretch' spacing={2}>
                        {azureADSummary.map((s, i) => (
                          <HStack key={i} justify='space-between'>
                            <Text fontSize='sm'>{s.type}</Text>
                            {s.error ? (
                              <Badge colorScheme='red'>{s.error}</Badge>
                            ) : (
                              <HStack spacing={2}>
                                <Badge colorScheme='green'>
                                  found {s.found}
                                </Badge>
                                {s.secrets > 0 && (
                                  <Badge colorScheme='blue'>
                                    {s.secrets} secrets
                                  </Badge>
                                )}
                                {s.certificates > 0 && (
                                  <Badge colorScheme='purple'>
                                    {s.certificates} certs
                                  </Badge>
                                )}
                              </HStack>
                            )}
                          </HStack>
                        ))}
                      </VStack>
                    </Box>
                  )}
                  <IntegrationImportTable
                    items={azureADItems}
                    selectedRows={selectedRowsAzureAD}
                    onToggleRow={i =>
                      setSelectedRowsAzureAD(prev => {
                        const n = new Set(prev);
                        n.has(i) ? n.delete(i) : n.add(i);
                        return n;
                      })
                    }
                    onToggleAll={() => {
                      if (selectedRowsAzureAD.size === azureADItems.length) {
                        setSelectedRowsAzureAD(new Set());
                      } else {
                        setSelectedRowsAzureAD(
                          new Set(azureADItems.map((_, i) => i))
                        );
                      }
                    }}
                    borderColor={border}
                    getDetailsForItem={getAzureADItemDetails}
                    onUpdateItem={updateAzureADItem}
                    duplicateIndices={azureADDuplicates}
                  />
                  <BulkIntegrationAssignment
                    selectedCount={selectedRowsAzureAD.size}
                    section={bulkSection}
                    onSectionChange={setBulkSection}
                    contactGroupId={bulkContactGroupId}
                    onContactGroupChange={setBulkContactGroupId}
                    contactGroups={contactGroups}
                    borderColor={border}
                  />
                </VStack>
              ) : null}

              {source === 'file' && parsing ? (
                <HStack>
                  <Text>Parsing…</Text>
                </HStack>
              ) : null}

              {error ? (
                <Alert status='error'>
                  <AlertIcon />
                  <VStack align='start' spacing={3} w='full'>
                    {(() => {
                      const parsed = parseErrorMessage(error);
                      const errorTextColor = isLight ? 'red.800' : 'red.200';
                      const helperTextColor = isLight ? 'gray.700' : 'gray.300';

                      if (!parsed)
                        return (
                          <Text fontSize='sm' color={errorTextColor}>
                            {error}
                          </Text>
                        );

                      // For multi-line errors (with bullet points), show full message with formatting
                      const isMultiLine = parsed.fullMessage.includes('\n');

                      return (
                        <>
                          {!isMultiLine && (
                            <Text
                              fontSize='sm'
                              fontWeight='semibold'
                              color={errorTextColor}
                            >
                              {parsed.shortMessage}
                            </Text>
                          )}
                          {parsed.commands && parsed.commands.length > 0 && (
                            <Box w='full'>
                              <Text
                                fontSize='xs'
                                mb={2}
                                color={helperTextColor}
                              >
                                Run these commands to fix:
                              </Text>
                              <VStack align='stretch' spacing={2}>
                                {parsed.commands.map((cmd, idx) => (
                                  <CopyableCodeBlock key={idx} code={cmd} />
                                ))}
                              </VStack>
                            </Box>
                          )}
                          {isMultiLine ? (
                            <Text
                              fontSize='sm'
                              color={errorTextColor}
                              whiteSpace='pre-wrap'
                            >
                              {parsed.fullMessage}
                            </Text>
                          ) : (
                            parsed.fullMessage !== parsed.shortMessage &&
                            !parsed.commands && (
                              <Text fontSize='xs' color={helperTextColor}>
                                {parsed.fullMessage}
                              </Text>
                            )
                          )}
                        </>
                      );
                    })()}
                    {failedRows && failedRows.length > 0 ? (
                      <Box maxH='120px' overflowY='auto' w='full'>
                        <Table size='xs' variant='simple'>
                          <Thead>
                            <Tr>
                              <Th>Row</Th>
                              <Th>Error</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {failedRows.slice(0, 10).map(fr => (
                              <Tr key={fr.index}>
                                <Td>{fr.index + 2}</Td>
                                <Td>{fr.error}</Td>
                              </Tr>
                            ))}
                          </Tbody>
                        </Table>
                        <HStack justify='space-between' mt={1}>
                          {failedRows.length > 10 ? (
                            <Text fontSize='xs' color={muted}>
                              Showing first 10 of {failedRows.length} errors.
                            </Text>
                          ) : (
                            <span />
                          )}
                          <Button
                            size='xs'
                            onClick={() => {
                              try {
                                const rows = [
                                  ['row', 'error'],
                                  ...failedRows.map(fr => [
                                    String(fr.index + 2),
                                    String(fr.error),
                                  ]),
                                ];
                                const csv = rows
                                  .map(r =>
                                    r
                                      .map(
                                        v =>
                                          `"${String(v).replace(/"/g, '""')}"`
                                      )
                                      .join(',')
                                  )
                                  .join('\n');
                                const blob = new Blob([csv], {
                                  type: 'text/csv;charset=utf-8;',
                                });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = 'import-errors.csv';
                                a.click();
                                setTimeout(
                                  () => URL.revokeObjectURL(url),
                                  1000
                                );
                              } catch (_) {}
                            }}
                          >
                            Download CSV
                          </Button>
                        </HStack>
                      </Box>
                    ) : null}
                    <Text fontSize='xs'>
                      Need help? See{' '}
                      <ChakraLink
                        onClick={() =>
                          window.open(
                            'https://tokentimer.ch/docs/tokens#import',
                            '_blank',
                            'noopener,noreferrer'
                          )
                        }
                        cursor='pointer'
                        textDecoration='underline'
                        color='blue.500'
                      >
                        import docs
                      </ChakraLink>
                      .
                    </Text>
                  </VStack>
                </Alert>
              ) : null}

              {source === 'file' && rows.length > 0 ? (
                <Box>
                  <HStack justify='space-between' mb={2}>
                    <Text fontSize='sm'>Detected {rows.length} valid rows</Text>
                    <Button
                      size='xs'
                      variant='outline'
                      onClick={() => {
                        if (selectedRowsFile.size === rows.length) {
                          setSelectedRowsFile(new Set());
                        } else {
                          setSelectedRowsFile(new Set(rows.map((_, i) => i)));
                        }
                      }}
                    >
                      {selectedRowsFile.size === rows.length
                        ? 'Deselect All'
                        : 'Select All'}
                    </Button>
                  </HStack>
                  {/* Warning banner for duplicates */}
                  {fileDuplicates.size > 0 &&
                    Array.from(selectedRowsFile).some(i =>
                      fileDuplicates.has(i)
                    ) && (
                      <Alert status='warning' borderRadius='md' mb={2} py={2}>
                        <AlertIcon />
                        <Text fontSize='sm'>
                          {(() => {
                            const selectedDuplicateCount = Array.from(
                              selectedRowsFile
                            ).filter(i => fileDuplicates.has(i)).length;
                            return `${selectedDuplicateCount} token${selectedDuplicateCount > 1 ? 's' : ''} already exist${selectedDuplicateCount === 1 ? 's' : ''} in this workspace. Importing will update the existing token${selectedDuplicateCount > 1 ? 's' : ''} with the new data.`;
                          })()}
                        </Text>
                      </Alert>
                    )}
                  <Box
                    maxH='260px'
                    overflowY='auto'
                    border='1px solid'
                    borderColor={border}
                    borderRadius='md'
                  >
                    <Table size='sm' variant='simple'>
                      <Thead>
                        <Tr>
                          <Th w='36px'></Th>
                          <Th>Name</Th>
                          <Th>Category</Th>
                          <Th>Type</Th>
                          <Th>Expires</Th>
                          <Th>Section</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {rows.map((r, i) => (
                          <Tr key={i}>
                            <Td>
                              <HStack spacing={1}>
                                <Checkbox
                                  isChecked={selectedRowsFile.has(i)}
                                  onChange={() =>
                                    setSelectedRowsFile(prev => {
                                      const n = new Set(prev);
                                      n.has(i) ? n.delete(i) : n.add(i);
                                      return n;
                                    })
                                  }
                                />
                                {fileDuplicates.has(i) && (
                                  <Tooltip
                                    label='This token already exists in this workspace. Importing will update the existing token with the new data.'
                                    hasArrow
                                    placement='top'
                                  >
                                    <Box
                                      as='span'
                                      color='orange.500'
                                      cursor='help'
                                    >
                                      <FiAlertTriangle size={14} />
                                    </Box>
                                  </Tooltip>
                                )}
                              </HStack>
                            </Td>
                            <Td>{r.name}</Td>
                            <Td>{r.category}</Td>
                            <Td>{r.type}</Td>
                            <Td>{r.expiresAt}</Td>
                            <Td>{r.section || ''}</Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  </Box>
                </Box>
              ) : null}

              {autoSyncManageMode && !isViewer ? (
                <Flex
                  direction={{ base: 'column', md: 'row' }}
                  gap={3}
                  pt={2}
                  justify={{ base: 'stretch', md: 'flex-end' }}
                  align={{ base: 'stretch', md: 'center' }}
                  flexWrap='wrap'
                >
                  <Button
                    {...dashboardModalInlineActionButtonProps}
                    {...outlineButtonProps}
                    colorScheme='red'
                    onClick={handleDisableAutoSync}
                    isLoading={savingAutoSync}
                    isDisabled={savingAutoSync}
                  >
                    Disable auto-sync
                  </Button>
                  <Button
                    {...dashboardModalInlineActionButtonProps}
                    {...outlineButtonProps}
                    onClick={handleRunAutoSyncNow}
                    isLoading={runningAutoSyncNow}
                    loadingText='Syncing...'
                    isDisabled={savingAutoSync || runningAutoSyncNow}
                  >
                    Sync now
                  </Button>
                  <Button
                    {...dashboardModalInlineActionButtonProps}
                    {...primaryButtonProps}
                    onClick={handleSaveAutoSyncChanges}
                    isLoading={savingAutoSync}
                    isDisabled={savingAutoSync}
                  >
                    Save changes
                  </Button>
                </Flex>
              ) : null}

              {isImporting ? (
                <Box>
                  <HStack justify='space-between' mb={1}>
                    <Text fontSize='sm'>
                      Importing… {progress.done}/{progress.total}
                    </Text>
                  </HStack>
                  <Progress
                    value={
                      progress.total
                        ? (progress.done / progress.total) * 100
                        : 0
                    }
                    size='sm'
                  />
                </Box>
              ) : null}
            </VStack>
          </ModalBody>
          <ModalFooter {...footerProps}>
            <Flex
              w='full'
              direction={{ base: 'column', sm: 'row' }}
              gap={3}
              justify={{ base: 'stretch', sm: 'flex-end' }}
              align={{ base: 'stretch', sm: 'center' }}
              flexWrap='wrap'
            >
              {!autoSyncManageMode ? (
                source === 'file' ? (
                  !isImporting ? (
                    <Button
                      {...primaryButtonProps}
                      onClick={onStartImport}
                      isDisabled={selectedRowsFile.size === 0}
                    >
                      Import {selectedRowsFile.size} selected
                    </Button>
                  ) : (
                    <Button {...outlineButtonProps} onClick={onCancelImport}>
                      Cancel
                    </Button>
                  )
                ) : source === 'vault' ? (
                  <Button
                    onClick={() => {
                      setIsImporting(true);
                      vaultFormRef.current?.importSelected();
                    }}
                    {...primaryButtonProps}
                    colorScheme='green'
                    isDisabled={integrationSelectedCount === 0 || isImporting}
                    isLoading={isImporting}
                  >
                    Import selected
                  </Button>
                ) : source === 'gitlab' ? (
                  <Button
                    onClick={() => {
                      setIsImporting(true);
                      gitlabFormRef.current?.importSelected();
                    }}
                    {...primaryButtonProps}
                    colorScheme='green'
                    isDisabled={integrationSelectedCount === 0 || isImporting}
                    isLoading={isImporting}
                  >
                    Import selected
                  </Button>
                ) : source === 'github' ? (
                  <Button
                    onClick={() => {
                      setIsImporting(true);
                      githubFormRef.current?.importSelected();
                    }}
                    {...primaryButtonProps}
                    colorScheme='green'
                    isDisabled={integrationSelectedCount === 0 || isImporting}
                    isLoading={isImporting}
                  >
                    Import selected
                  </Button>
                ) : source === 'aws' ? (
                  <Button
                    onClick={() => {
                      setIsImporting(true);
                      awsFormRef.current?.importSelected();
                    }}
                    {...primaryButtonProps}
                    colorScheme='green'
                    isDisabled={integrationSelectedCount === 0 || isImporting}
                    isLoading={isImporting}
                  >
                    Import selected
                  </Button>
                ) : source === 'azure' ? (
                  <Button
                    onClick={() => {
                      setIsImporting(true);
                      azureFormRef.current?.importSelected();
                    }}
                    {...primaryButtonProps}
                    colorScheme='green'
                    isDisabled={integrationSelectedCount === 0 || isImporting}
                    isLoading={isImporting}
                  >
                    Import selected
                  </Button>
                ) : source === 'azure-ad' ? (
                  <Button
                    onClick={importAzureADSelected}
                    {...primaryButtonProps}
                    colorScheme='green'
                    isDisabled={selectedRowsAzureAD.size === 0 || isImporting}
                    isLoading={isImporting}
                  >
                    Import selected
                  </Button>
                ) : source === 'gcp' ? (
                  <Button
                    onClick={() => {
                      setIsImporting(true);
                      gcpFormRef.current?.importSelected();
                    }}
                    {...primaryButtonProps}
                    colorScheme='green'
                    isDisabled={integrationSelectedCount === 0 || isImporting}
                    isLoading={isImporting}
                  >
                    Import selected
                  </Button>
                ) : null
              ) : null}
              <Button {...outlineButtonProps} onClick={onCloseInternal}>
                Close
              </Button>
              {source !== 'file' && !isViewer && !hasAutoSync ? (
                <Tooltip
                  label={
                    !isAutoSyncAllowed
                      ? 'Auto-sync for this provider is not available in this edition'
                      : !scanSucceededFor.has(source)
                        ? 'Run a successful scan first to enable auto-sync'
                        : 'Save current credentials for scheduled automatic scans'
                  }
                  fontSize='xs'
                  hasArrow
                  placement='top'
                >
                  <Box as='span' display='inline-block'>
                    <Button
                      {...outlineButtonProps}
                      colorScheme='blue'
                      onClick={handleEnableAutoSync}
                      isLoading={savingAutoSync}
                      isDisabled={
                        !isAutoSyncAllowed || !scanSucceededFor.has(source)
                      }
                      opacity={
                        isAutoSyncAllowed && scanSucceededFor.has(source)
                          ? 1
                          : 0.5
                      }
                    >
                      Enable auto-sync
                      {!isAutoSyncAllowed && ' (unavailable)'}
                    </Button>
                  </Box>
                </Tooltip>
              ) : null}
            </Flex>
          </ModalFooter>
        </DashboardModalFrame>
      </Modal>

      {/* Enable auto-sync modal */}
      <Modal
        isOpen={isEnableAutoSyncOpen}
        onClose={onEnableAutoSyncClose}
        isCentered
        size='md'
        scrollBehavior='inside'
      >
        <ModalOverlay {...overlayProps} />
        <DashboardModalFrame maxW='520px'>
          <ModalHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Enable Auto-Sync
            </DashboardModalTitle>
            <DashboardModalDescription>
              Save credentials for scheduled infrastructure scans.
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton {...closeButtonProps} />
          <ModalBody {...bodyProps}>
            <VStack spacing={4} align='stretch'>
              <Alert status='info' borderRadius='md'>
                <AlertIcon />
                <Text fontSize='sm'>
                  Your credentials will be encrypted and stored to run scheduled
                  scans automatically. You can change the schedule and
                  credentials later from the Manage auto-sync tab.
                </Text>
              </Alert>
              <Box {...fieldProps} p={3}>
                <Text fontSize='sm' fontWeight='semibold' mb={1}>
                  Provider: {source}
                </Text>
              </Box>
              <HStack spacing={4} align='flex-end'>
                <FormControl flex='1'>
                  <FormLabel fontSize='sm'>Frequency</FormLabel>
                  <Select
                    size='sm'
                    value={enableSyncFrequency}
                    onChange={e => setEnableSyncFrequency(e.target.value)}
                  >
                    <option value='daily'>Daily</option>
                    <option value='weekly'>Weekly</option>
                    <option value='monthly'>Monthly</option>
                  </Select>
                </FormControl>
                <FormControl flex='1'>
                  <FormLabel fontSize='sm'>Time</FormLabel>
                  <Input
                    size='sm'
                    type='time'
                    value={enableSyncTime}
                    onChange={e => setEnableSyncTime(e.target.value)}
                  />
                </FormControl>
              </HStack>
              <FormControl>
                <FormLabel fontSize='sm'>Timezone</FormLabel>
                <Select
                  size='sm'
                  value={enableSyncTz}
                  onChange={e => setEnableSyncTz(e.target.value)}
                >
                  {timezoneList.map(tz => (
                    <option key={tz} value={tz}>
                      {tz.replace(/_/g, ' ')}
                    </option>
                  ))}
                </Select>
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter {...footerProps}>
            <HStack w='full' justify='flex-end' flexWrap='wrap' spacing={3}>
              <Button
                {...outlineButtonProps}
                onClick={onEnableAutoSyncClose}
              >
                Cancel
              </Button>
              <Button
                {...primaryButtonProps}
                onClick={confirmEnableAutoSync}
                isLoading={savingAutoSync}
              >
                Enable Auto-Sync
              </Button>
            </HStack>
          </ModalFooter>
        </DashboardModalFrame>
      </Modal>

      {/* Disable auto-sync confirmation modal */}
      <Modal
        isOpen={isDisableAutoSyncOpen}
        onClose={onDisableAutoSyncClose}
        isCentered
        size='sm'
        scrollBehavior='inside'
      >
        <ModalOverlay {...overlayProps} />
        <DashboardModalFrame maxW='460px'>
          <ModalHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Disable Auto-Sync
            </DashboardModalTitle>
            <DashboardModalDescription>
              Stop scheduled scans for this provider.
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton {...closeButtonProps} />
          <ModalBody {...bodyProps}>
            <VStack spacing={3} align='stretch'>
              <Alert status='warning' borderRadius='md'>
                <AlertIcon />
                <Text fontSize='sm'>
                  This will stop scheduled scans and delete the saved
                  credentials for this integration.
                </Text>
              </Alert>
              {autoSyncConfig && (
                <Box {...fieldProps} p={3}>
                  <Text fontSize='sm'>
                    <Text as='span' fontWeight='semibold'>
                      Provider:
                    </Text>{' '}
                    {autoSyncConfig.provider}
                  </Text>
                  <Text fontSize='sm'>
                    <Text as='span' fontWeight='semibold'>
                      Schedule:
                    </Text>{' '}
                    {autoSyncConfig.frequency || 'daily'} at{' '}
                    {autoSyncConfig.schedule_time || '09:00'} (
                    {autoSyncConfig.schedule_tz || 'UTC'})
                  </Text>
                  {autoSyncConfig.last_sync_at && (
                    <Text fontSize='sm'>
                      <Text as='span' fontWeight='semibold'>
                        Last sync:
                      </Text>{' '}
                      {new Date(autoSyncConfig.last_sync_at).toLocaleString()}
                    </Text>
                  )}
                </Box>
              )}
            </VStack>
          </ModalBody>
          <ModalFooter {...footerProps}>
            <HStack w='full' justify='flex-end' flexWrap='wrap' spacing={3}>
              <Button {...outlineButtonProps} onClick={onDisableAutoSyncClose}>
                Cancel
              </Button>
              <Button
                {...dangerButtonProps}
                onClick={confirmDisableAutoSync}
              >
                Disable Auto-Sync
              </Button>
            </HStack>
          </ModalFooter>
        </DashboardModalFrame>
      </Modal>
    </>
  );
}
