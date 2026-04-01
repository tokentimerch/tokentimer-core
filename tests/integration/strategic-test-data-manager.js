const { request, expect } = require("./test-server");
const { logger } = require("./logger");

/**
 * Strategic Test Data Manager
 *
 * This module implements the strategic testing approach with:
 * 1. Smart field grouping
 * 2. Representative combinations
 * 3. Category-based testing
 * 4. Constraint-based testing
 */

// Helper function to generate future dates for test tokens
const getFutureDate = (daysInFuture = 90) => {
  return new Date(Date.now() + daysInFuture * 24 * 60 * 60 * 1000)
    .toISOString()
    .split("T")[0];
};

const TEST_BASE_URL = process.env.TEST_API_URL || "http://localhost:4000";

// Token type definitions
const TOKEN_DEFINITIONS = {
  cert: ["ssl_cert", "tls_cert", "code_signing", "client_cert"],
  key_secret: ["api_key", "secret", "password", "encryption_key", "ssh_key"],
  license: ["software_license", "service_subscription"],
  general: ["domain_registration", "other", "document", "membership"],
};

// Smart field grouping - logically related fields
const SMART_FIELD_GROUPS = {
  cert_identity: {
    domains: ["example.com", "api.example.com"],
    subject: "CN=example.com, O=Test Corp, C=US",
    issuer: "Let's Encrypt",
    serial_number: "1A2B3C4D5E6F7890",
  },
  cert_technical: {
    algorithm: "RSA-SHA256",
    key_size: 2048,
  },
  general_technical: {
    description: "General technical configuration",
  },
  algorithm_technical: {
    algorithm: "AES-256",
  },
  key_operational: {
    location: "/etc/keys/",
    used_by: "API Server",
  },
  key_security: {
    description: "Encryption key for sensitive data",
  },
  license_business: {
    vendor: "Microsoft Corporation",
    license_type: "Enterprise",
    cost: 1299.99,
  },
  license_management: {
    renewal_url: "https://admin.microsoft.com/licenses",
    renewal_date: getFutureDate(90),
    contacts: "licensing@company.com",
  },
  common_operational: {
    location: "/var/lib/documents/",
    used_by: "HR Department",
    contacts: "admin@company.com",
  },
  common_metadata: {
    description: "Important company resource",
    notes: "Requires annual review",
    renewal_date: getFutureDate(180),
  },
};

// Representative combinations
const REPRESENTATIVE_COMBINATIONS = [
  { name: "minimal", description: "Only required fields", fields: {} },
  {
    name: "cert_identity_only",
    description: "Certificate identity fields only",
    fields: SMART_FIELD_GROUPS.cert_identity,
  },
  {
    name: "cert_technical_only",
    description: "Certificate technical fields only",
    fields: SMART_FIELD_GROUPS.cert_technical,
  },
  {
    name: "general_technical_only",
    description: "General technical fields only",
    fields: SMART_FIELD_GROUPS.general_technical,
  },
  {
    name: "algorithm_technical_only",
    description: "Algorithm technical fields only",
    fields: SMART_FIELD_GROUPS.algorithm_technical,
  },
  {
    name: "key_operational_only",
    description: "Key operational fields only",
    fields: SMART_FIELD_GROUPS.key_operational,
  },
  {
    name: "key_security_only",
    description: "Key security fields only",
    fields: SMART_FIELD_GROUPS.key_security,
  },
  {
    name: "license_business_only",
    description: "License business fields only",
    fields: SMART_FIELD_GROUPS.license_business,
  },
  {
    name: "license_management_only",
    description: "License management fields only",
    fields: SMART_FIELD_GROUPS.license_management,
  },
  {
    name: "common_operational_only",
    description: "Common operational fields only",
    fields: SMART_FIELD_GROUPS.common_operational,
  },
  {
    name: "common_metadata_only",
    description: "Common metadata fields only",
    fields: SMART_FIELD_GROUPS.common_metadata,
  },
  {
    name: "complete_certificate",
    description: "All certificate-related fields",
    fields: {
      ...SMART_FIELD_GROUPS.cert_identity,
      ...SMART_FIELD_GROUPS.cert_technical,
      ...SMART_FIELD_GROUPS.common_operational,
    },
  },
  {
    name: "complete_key_secret",
    description: "All key/secret-related fields",
    fields: {
      ...SMART_FIELD_GROUPS.key_operational,
      ...SMART_FIELD_GROUPS.key_security,
      ...SMART_FIELD_GROUPS.common_metadata,
    },
  },
  {
    name: "complete_license",
    description: "All license-related fields",
    fields: {
      ...SMART_FIELD_GROUPS.license_business,
      ...SMART_FIELD_GROUPS.license_management,
      ...SMART_FIELD_GROUPS.common_operational,
    },
  },
  {
    name: "mixed_technical",
    description: "Technical fields from different categories",
    fields: {
      ...SMART_FIELD_GROUPS.cert_technical,
      ...SMART_FIELD_GROUPS.key_security,
    },
  },
  {
    name: "mixed_operational",
    description: "Operational fields from different categories",
    fields: {
      ...SMART_FIELD_GROUPS.key_operational,
      ...SMART_FIELD_GROUPS.license_management,
      ...SMART_FIELD_GROUPS.common_operational,
    },
  },
  {
    name: "maximum_fields",
    description: "All possible fields populated",
    fields: {
      ...SMART_FIELD_GROUPS.cert_identity,
      ...SMART_FIELD_GROUPS.cert_technical,
      ...SMART_FIELD_GROUPS.key_operational,
      ...SMART_FIELD_GROUPS.key_security,
      ...SMART_FIELD_GROUPS.license_business,
      ...SMART_FIELD_GROUPS.license_management,
      ...SMART_FIELD_GROUPS.common_operational,
      ...SMART_FIELD_GROUPS.common_metadata,
    },
  },
];

// Constraint-focused test data
const CONSTRAINT_TEST_DATA = {
  boundary_valid: {
    name: "ABC",
    name_max: "A".repeat(100),
    location_max: "B".repeat(500),
    issuer_max: "C".repeat(255),
    key_size_min: 1,
    key_size_large: 65536,
    cost_zero: 0,
    cost_large: 999999999999.99,
  },
  boundary_invalid: {
    name_short: "AB",
    name_long: "A".repeat(101),
    location_long: "B".repeat(501),
    issuer_long: "C".repeat(256),
    key_size_negative: -1,
    key_size_zero: 0,
    cost_negative: -100.5,
    cost_huge: 1000000000000.0,
  },
  type_invalid: {
    key_size_string: "not_a_number",
    cost_string: "not_a_decimal",
    renewal_date_invalid: "not_a_date",
  },
  security_malicious: {
    sql_injection: "'; DROP TABLE tokens; --",
    xss_script: '<script>alert("xss")</script>',
    xss_img: '<img src=x onerror=alert("xss")>',
    command_injection: "$(rm -rf /)",
    path_traversal: "../../../etc/passwd",
  },
};

const isValidCombination = (category, fields, tokenType = null) => {
  if (fields.name && fields.name.length < 3) return false;
  if (fields.key_size && fields.key_size <= 0) return false;
  if (fields.cost && fields.cost < 0) return false;

  const lengthChecks = [
    { field: "location", max: 500 },
    { field: "issuer", max: 255 },
    { field: "serial_number", max: 255 },
    { field: "algorithm", max: 100 },
    { field: "vendor", max: 255 },
  ];

  for (const check of lengthChecks) {
    if (fields[check.field] && fields[check.field].length > check.max) {
      return false;
    }
  }

  if (category === "key_secret") {
    if (
      fields.domains ||
      fields.issuer ||
      fields.subject ||
      fields.serial_number
    )
      return false;
    if (fields.key_size && fields.key_size === 2048) return false;
    if (fields.algorithm && tokenType) {
      const algorithmCompatibleTypes = ["encryption_key", "ssh_key", "secret"];
      if (!algorithmCompatibleTypes.includes(tokenType)) return false;
    }
  } else if (category === "cert") {
    if (fields.vendor || fields.license_type || fields.cost) return false;
    if (fields.algorithm && tokenType) {
      const algorithmCompatibleTypes = [
        "ssl_cert",
        "tls_cert",
        "code_signing",
        "client_cert",
      ];
      if (!algorithmCompatibleTypes.includes(tokenType)) return false;
    }
  } else if (category === "license") {
    if (
      fields.domains ||
      fields.issuer ||
      fields.subject ||
      fields.serial_number
    )
      return false;
    if (fields.key_size && fields.key_size === 2048) return false;
    if (fields.algorithm) return false;
  } else if (category === "general") {
    if (
      fields.domains ||
      fields.issuer ||
      fields.subject ||
      fields.serial_number
    )
      return false;
    if (fields.key_size && fields.key_size === 2048) return false;
    if (fields.algorithm) return false;
  }

  return true;
};

const generateCategoryScenarios = (category) => {
  const tokenTypes = TOKEN_DEFINITIONS[category];
  const combinations = REPRESENTATIVE_COMBINATIONS;
  const scenarios = [];

  tokenTypes.forEach((tokenType) => {
    combinations.forEach((combination) => {
      if (isValidCombination(category, combination.fields, tokenType)) {
        scenarios.push({
          name: `${tokenType}_with_${combination.name}`,
          description: `${tokenType} token with ${combination.description}`,
          tokenType: tokenType,
          category: category,
          fields: combination.fields,
          expectedSuccess: true,
        });
      }
    });
  });

  return scenarios;
};

const generateConstraintTests = () => {
  const tests = [];

  Object.entries(CONSTRAINT_TEST_DATA.boundary_valid).forEach(
    ([fieldName, value]) => {
      tests.push({
        name: `boundary_valid_${fieldName}`,
        description: `Valid boundary value for ${fieldName}`,
        fields: { [fieldName]: value },
        expectedSuccess: true,
        testType: "boundary",
      });
    },
  );

  const backendValidatedFields = ["name_short", "name_long"];
  backendValidatedFields.forEach((fieldName) => {
    const value = CONSTRAINT_TEST_DATA.boundary_invalid[fieldName];
    if (value) {
      tests.push({
        name: `boundary_invalid_${fieldName}`,
        description: `Invalid boundary value for ${fieldName}`,
        fields: { name: value },
        expectedSuccess: false,
        testType: "boundary",
      });
    }
  });

  const backendTypeValidatedFields = ["key_size_string", "cost_string"];
  backendTypeValidatedFields.forEach((fieldName) => {
    const value = CONSTRAINT_TEST_DATA.type_invalid[fieldName];
    if (value) {
      const fieldNameMap = { key_size_string: "key_size", cost_string: "cost" };
      const actualFieldName = fieldNameMap[fieldName];
      tests.push({
        name: `type_invalid_${fieldName}`,
        description: `Invalid type for ${fieldName}`,
        fields: { [actualFieldName]: value },
        expectedSuccess: false,
        testType: "type",
      });
    }
  });

  Object.entries(CONSTRAINT_TEST_DATA.security_malicious).forEach(
    ([attackName, value]) => {
      tests.push({
        name: `security_${attackName}`,
        description: `Security test: ${attackName}`,
        fields: { description: value, notes: value },
        expectedSuccess: true,
        testType: "security",
      });
    },
  );

  return tests;
};

const executeScenario = async (scenario, sessionCookie, workspaceId = null) => {
  const tokenData = {
    name: scenario.name || "Test Token",
    type: scenario.tokenType || "api_key",
    category: scenario.category || "key_secret",
    expiresAt: getFutureDate(90),
    ...scenario.fields,
  };

  if (workspaceId) tokenData.workspace_id = workspaceId;

  try {
    const response = await request(TEST_BASE_URL)
      .post("/api/tokens")
      .set("Cookie", sessionCookie)
      .send(tokenData);

    return {
      scenario: scenario.name,
      success: response.status === 201,
      expectedSuccess: scenario.expectedSuccess,
      status: response.status,
      body: response.body,
      match: (response.status === 201) === scenario.expectedSuccess,
    };
  } catch (error) {
    return {
      scenario: scenario.name,
      success: false,
      expectedSuccess: scenario.expectedSuccess,
      error: error.message,
      match: !scenario.expectedSuccess,
    };
  }
};

const createStrategicTestDataset = async (datasetName, options = {}) => {
  const {
    includeAllCategories = true,
    includeConstraintTests = true,
    maxTokensPerCategory = 10,
  } = options;

  const dataset = {
    id: `strategic_${Date.now()}`,
    name: datasetName,
    created: Date.now(),
    scenarios: [],
    stats: {
      totalScenarios: 0,
      successScenarios: 0,
      failureScenarios: 0,
      securityScenarios: 0,
    },
  };

  if (includeAllCategories) {
    for (const category of Object.keys(TOKEN_DEFINITIONS)) {
      const scenarios = generateCategoryScenarios(category).slice(
        0,
        maxTokensPerCategory,
      );
      dataset.scenarios.push(...scenarios);
      dataset.stats.totalScenarios += scenarios.length;
      dataset.stats.successScenarios += scenarios.filter(
        (s) => s.expectedSuccess,
      ).length;
      dataset.stats.failureScenarios += scenarios.filter(
        (s) => !s.expectedSuccess,
      ).length;
    }
  }

  if (includeConstraintTests) {
    const tests = generateConstraintTests();
    dataset.scenarios.push(...tests);
    dataset.stats.totalScenarios += tests.length;
    dataset.stats.successScenarios += tests.filter(
      (s) => s.expectedSuccess,
    ).length;
    dataset.stats.failureScenarios += tests.filter(
      (s) => !s.expectedSuccess,
    ).length;
    dataset.stats.securityScenarios += tests.filter(
      (s) => s.testType === "security",
    ).length;
  }

  return dataset;
};

const runStrategicTestSuite = async (dataset, sessionCookie, options = {}) => {
  const {
    maxConcurrent = 5,
    stopOnFirstFailure = false,
    includeDetailedResults = true,
    workspaceId = null,
  } = options;

  const results = {
    startTime: Date.now(),
    endTime: null,
    totalScenarios: dataset.scenarios.length,
    executed: 0,
    passed: 0,
    failed: 0,
    matches: 0,
    mismatches: 0,
    scenarios: [],
  };

  logger.info(`Starting strategic test suite: ${dataset.name}`);

  for (let i = 0; i < dataset.scenarios.length; i += maxConcurrent) {
    const batch = dataset.scenarios.slice(i, i + maxConcurrent);
    const batchResults = await Promise.all(
      batch.map((s) => executeScenario(s, sessionCookie, workspaceId)),
    );

    for (const result of batchResults) {
      results.executed++;
      if (result.success) results.passed++;
      else results.failed++;
      if (result.match) results.matches++;
      else results.mismatches++;
      if (includeDetailedResults) results.scenarios.push(result);
      if (stopOnFirstFailure && !result.match) break;
    }

    const progress = Math.round(
      (results.executed / results.totalScenarios) * 100,
    );
    logger.info(
      `Progress: ${progress}% (${results.executed}/${results.totalScenarios})`,
    );
    if (stopOnFirstFailure && results.mismatches > 0) break;
  }

  results.endTime = Date.now();
  results.duration = results.endTime - results.startTime;
  return results;
};

const generateSummaryReport = (results) => {
  const report = {
    overview: {
      totalScenarios: results.totalScenarios,
      executed: results.executed,
      successRate: Math.round((results.passed / results.executed) * 100),
      accuracyRate: Math.round((results.matches / results.executed) * 100),
      duration: `${Math.round(results.duration / 1000)}s`,
    },
    mismatches: results.scenarios
      .filter((r) => !r.match)
      .map((r) => ({
        scenario: r.scenario,
        expected: r.expectedSuccess ? "success" : "failure",
        actual: r.success ? "success" : "failure",
        status: r.status,
        error: r.error,
      })),
  };
  return report;
};

module.exports = {
  TOKEN_DEFINITIONS,
  SMART_FIELD_GROUPS,
  createStrategicTestDataset,
  runStrategicTestSuite,
  generateSummaryReport,
};
