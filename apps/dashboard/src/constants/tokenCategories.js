/**
 * Token categories, types, and per-category field sets.
 *
 * Shared between the main dashboard (token cards, add/edit forms,
 * TokenDetailModal) and any other page that needs to render a token with
 * the same category/type labels and colors, e.g. opening TokenDetailModal
 * for a certificate's underlying token from the CertOps certificates panel.
 */
export const TOKEN_CATEGORIES = [
  {
    value: 'cert',
    label: 'Certificate',
    description: 'SSL/TLS certificates, domain certificates',
    color: 'blue',
    bgColor: 'blue.100',
    borderColor: 'blue.400',
    types: [
      { value: 'ssl_cert', label: 'SSL Certificate' },
      { value: 'tls_cert', label: 'TLS Certificate' },
      { value: 'code_signing', label: 'Code Signing' },
      { value: 'client_cert', label: 'Client Certificate' },
    ],
    fields: [
      'domains',
      'issuer',
      'serial_number',
      'subject',
      'renewal_url',
      'contacts',
    ],
  },
  {
    value: 'key_secret',
    label: 'Key/Secret',
    description: 'API keys, secrets, passwords, encryption keys',
    color: 'green',
    bgColor: 'green.100',
    borderColor: 'green.500',
    types: [
      { value: 'api_key', label: 'API Key' },
      { value: 'secret', label: 'Secret' },
      { value: 'password', label: 'Password' },
      { value: 'encryption_key', label: 'Encryption Key' },
      { value: 'ssh_key', label: 'SSH Key' },
    ],
    fields: ['location', 'used_by', 'renewal_url', 'description', 'contacts'],
    // Fields that only apply to specific types
    conditionalFields: {
      encryption_key: ['algorithm', 'key_size'],
      ssh_key: ['algorithm', 'key_size'],
    },
  },
  {
    value: 'license',
    label: 'License',
    description: 'Software licenses, service subscriptions',
    color: 'purple',
    bgColor: 'purple.100',
    borderColor: 'purple.500',
    types: [
      { value: 'software_license', label: 'Software License' },
      { value: 'service_subscription', label: 'Service Subscription' },
      { value: 'domain_registration', label: 'Domain Registration' },
    ],
    fields: [
      'vendor',
      'license_type',
      'cost',
      'renewal_url',
      'renewal_date',
      'contacts',
    ],
  },
  {
    value: 'general',
    label: 'General',
    description: 'Other expiring items',
    color: 'gray',
    bgColor: 'gray.100',
    borderColor: 'gray.500',
    types: [
      { value: 'other', label: 'Other' },
      { value: 'document', label: 'Document' },
      { value: 'membership', label: 'Membership' },
    ],
    fields: ['location', 'used_by', 'renewal_url', 'contacts'],
  },
];
