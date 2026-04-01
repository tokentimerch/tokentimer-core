// Mock data for Product Tour
export const TOUR_MOCK_TOKENS = [
  {
    id: 'mock-token-1',
    name: 'Production Database API Key',
    type: 'api_key',
    category: 'key_secret',
    expiresAt: new Date(Date.now() + 86400000 * -2).toISOString().split('T')[0], // Expired 2 days ago
    section: 'production',
    description: 'Main API key for the production database',
    location: 'AWS Secrets Manager',
    used_by: 'Backend Service',
  },
  {
    id: 'mock-token-2',
    name: 'Analytics Service License',
    type: 'license_key',
    category: 'license',
    expiresAt: new Date(Date.now() + 86400000 * 90).toISOString().split('T')[0], // Expires in 90 days
    section: 'tools',
    description: 'License key for the analytics service',
    vendor: 'AnalyticsCorp',
    license_type: 'Enterprise',
  },
  {
    id: 'mock-token-3',
    name: 'Wildcard SSL Certificate',
    type: 'ssl_cert',
    category: 'cert',
    expiresAt: new Date(Date.now() + 86400000 * 25).toISOString().split('T')[0], // Expires in 25 days
    section: 'production',
    description: 'Wildcard certificate for *.example.com',
    domains: ['*.example.com', 'example.com'],
    issuer: 'DigiCert',
    serial_number: '73:5F:...',
    subject: 'CN=*.example.com, O=Example Corp',
  },
  {
    id: 'mock-token-4',
    name: 'General Access Token',
    type: 'other',
    category: 'general',
    expiresAt: new Date(Date.now() + 86400000 * 5).toISOString().split('T')[0], // Expires in 5 days
    section: 'general',
    description: 'General purpose access token for various services',
  },
];

export const TOUR_MOCK_WORKSPACE_CONTACTS = [
  {
    id: 'mock-contact-1',
    first_name: 'Alice',
    last_name: 'DevOps',
    details: {
      email: 'alice@example.com',
      title: 'Lead Engineer',
      department: 'Infrastructure',
    },
    phone_e164: '+15550101',
  },
  {
    id: 'mock-contact-2',
    first_name: 'Security',
    last_name: 'Team',
    details: {
      email: 'security@example.com',
      department: 'Security',
    },
    phone_e164: null,
  },
];

export const TOUR_MOCK_CONTACT_GROUPS = [
  {
    id: 'mock-group-1',
    name: 'DevOps Team',
    description: 'Main DevOps team for infrastructure alerts',
    email_contact_ids: ['mock-contact-1', 'mock-contact-2'],
    whatsapp_contact_ids: ['mock-contact-1'],
    thresholds: [1, 7, 30],
  },
  {
    id: 'mock-group-2',
    name: 'Security Team',
    description: 'Security team for critical alerts',
    email_contact_ids: ['mock-contact-3'],
    whatsapp_contact_ids: [],
    thresholds: [1, 3, 7, 14],
  },
];

export const TOUR_MOCK_WEBHOOKS = [
  {
    url: 'https://example.com/slack-webhook-placeholder',
    name: 'On-call Slack',
    kind: 'slack',
    verified: true,
    verifiedUrl: 'https://example.com/slack-webhook-placeholder',
    severity: '',
    template: '',
    routingKey: '',
  },
  {
    url: 'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz',
    name: 'Incident Discord',
    kind: 'discord',
    verified: true,
    verifiedUrl:
      'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz',
    severity: '',
    template: '',
    routingKey: '',
  },
];
