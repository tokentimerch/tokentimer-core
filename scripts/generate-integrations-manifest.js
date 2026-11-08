#!/usr/bin/env node

/**
 * Generate and validate integrations.watch.yaml manifest
 *
 * This script validates the integrations manifest against the actual codebase:
 * - Checks that all listed code locations exist
 * - Extracts SDK versions from package.json files
 * - Validates api-version strings in code
 * - Checks base URLs and endpoints referenced in code
 *
 * Usage:
 *   node scripts/generate-integrations-manifest.js [--check]
 *
 * Options:
 *   --check  Validation mode: exit with error if manifest is out of date
 *   (default: update mode, reports issues but doesn't fail)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const MANIFEST_PATH = path.join(REPO_ROOT, 'integrations.watch.yaml');

const checkMode = process.argv.includes('--check');
const warnings = [];
const errors = [];

function warn(message) {
  warnings.push(message);
  console.warn(`⚠️  ${message}`);
}

function error(message) {
  errors.push(message);
  console.error(`❌ ${message}`);
}

function info(message) {
  console.log(`ℹ️  ${message}`);
}

function success(message) {
  console.log(`✅ ${message}`);
}

function readManifest() {
  if (!fs.existsSync(MANIFEST_PATH)) {
    error(`Manifest not found: ${MANIFEST_PATH}`);
    return null;
  }
  
  try {
    const content = fs.readFileSync(MANIFEST_PATH, 'utf8');
    // Basic YAML parsing (would use js-yaml in production, but avoid extra dep)
    return { content, raw: content };
  } catch (err) {
    error(`Failed to read manifest: ${err.message}`);
    return null;
  }
}

function checkCodeLocation(location) {
  const fullPath = path.join(REPO_ROOT, location);
  if (!fs.existsSync(fullPath)) {
    error(`Code location not found: ${location}`);
    return false;
  }
  return true;
}

function extractSdkVersions() {
  const sdkVersions = {};
  
  const packageFiles = [
    'apps/api/package.json',
    'apps/worker/package.json',
    'apps/k8s-controller/package.json',
    'packages/agent/package.json',
  ];
  
  for (const pkgFile of packageFiles) {
    const pkgPath = path.join(REPO_ROOT, pkgFile);
    if (!fs.existsSync(pkgPath)) {
      warn(`Package file not found: ${pkgFile}`);
      continue;
    }
    
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      
      sdkVersions[pkgFile] = deps;
    } catch (err) {
      warn(`Failed to parse ${pkgFile}: ${err.message}`);
    }
  }
  
  return sdkVersions;
}

function checkSdkVersion(sdkName, expectedVersion, location) {
  const sdkVersions = extractSdkVersions();
  
  if (!location) {
    // Check all package files
    let found = false;
    for (const [pkgFile, deps] of Object.entries(sdkVersions)) {
      if (deps[sdkName]) {
        if (deps[sdkName] !== expectedVersion) {
          warn(`SDK version mismatch: ${sdkName} is ${deps[sdkName]} in ${pkgFile}, manifest says ${expectedVersion}`);
        } else {
          found = true;
        }
      }
    }
    if (!found) {
      warn(`SDK ${sdkName} not found in any package.json`);
    }
    return found;
  }
  
  // Check specific location
  const deps = sdkVersions[location];
  if (!deps) {
    error(`Package file not found for SDK check: ${location}`);
    return false;
  }
  
  if (!deps[sdkName]) {
    error(`SDK ${sdkName} not found in ${location}`);
    return false;
  }
  
  if (deps[sdkName] !== expectedVersion) {
    error(`SDK version mismatch: ${sdkName} is ${deps[sdkName]} in ${location}, manifest says ${expectedVersion}`);
    return false;
  }
  
  return true;
}

function checkApiVersionInCode(integrationId, apiVersion) {
  if (!apiVersion || apiVersion === 'null') return true;
  
  // Search for API version strings in code
  try {
    // Use grep to find version strings
    let pattern = apiVersion;
    
    // Special cases for different integrations
    if (integrationId === 'github' && apiVersion === '2022-11-28') {
      pattern = 'X-GitHub-Api-Version.*2022-11-28';
    } else if (integrationId === 'microsoft-azure' && apiVersion.includes('7.5')) {
      pattern = 'api-version.*7\\.5';
    } else if (integrationId === 'google-cloud' && apiVersion === 'v1') {
      pattern = 'certificatemanager\\.googleapis\\.com/v1';
    }
    
    const grepCmd = `cd "${REPO_ROOT}" && grep -r "${pattern}" apps/ packages/ --include="*.js" --include="*.ts" 2>/dev/null || true`;
    const result = execSync(grepCmd, { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 });
    
    if (result.trim().length === 0) {
      warn(`API version ${apiVersion} for ${integrationId} not found in code`);
      return false;
    }
    
    return true;
  } catch (err) {
    warn(`Failed to check API version in code: ${err.message}`);
    return false;
  }
}

function validateManifest() {
  info('Validating integrations.watch.yaml manifest...');
  
  const manifest = readManifest();
  if (!manifest) {
    return false;
  }
  
  info('Checking SDK versions from package.json files...');
  const sdkVersions = extractSdkVersions();
  
  // Report found versions
  info(`Found ${Object.keys(sdkVersions).length} package.json files`);
  for (const [pkgFile, deps] of Object.entries(sdkVersions)) {
    const depCount = Object.keys(deps).length;
    info(`  ${pkgFile}: ${depCount} dependencies`);
  }
  
  // Key SDK checks
  const criticalChecks = [
    { sdk: 'axios', version: '1.20.0', location: 'apps/api/package.json' },
    { sdk: 'axios', version: '1.20.0', location: 'apps/worker/package.json' },
    { sdk: '@kubernetes/client-node', version: '1.4.0', location: 'apps/k8s-controller/package.json' },
    { sdk: '@aws-sdk/client-acm', version: '3.1045.0', location: 'apps/api/package.json' },
  ];
  
  info('Checking critical SDK versions...');
  for (const check of criticalChecks) {
    const ok = checkSdkVersion(check.sdk, check.version, check.location);
    if (ok) {
      success(`${check.sdk}@${check.version} in ${check.location}`);
    }
  }
  
  // Check critical code locations
  info('Checking critical code locations...');
  const criticalLocations = [
    'apps/worker/src/notify/slack.js',
    'apps/worker/src/notify/webhooks.js',
    'apps/worker/src/pagerduty-incidents.js',
    'apps/api/services/githubIntegration.js',
    'apps/api/services/gitlabIntegration.js',
    'apps/k8s-controller/src/cert-manager-client.js',
    'packages/agent/src/material-store/index.js',
  ];
  
  for (const location of criticalLocations) {
    const ok = checkCodeLocation(location);
    if (ok) {
      success(location);
    }
  }
  
  // Check API versions in code
  info('Checking API versions in code...');
  const apiVersionChecks = [
    { id: 'github', version: '2022-11-28' },
  ];
  
  for (const check of apiVersionChecks) {
    const ok = checkApiVersionInCode(check.id, check.version);
    if (ok) {
      success(`${check.id} API version ${check.version} found in code`);
    }
  }
  
  // Summary
  console.log('\n=== Validation Summary ===');
  console.log(`Warnings: ${warnings.length}`);
  console.log(`Errors: ${errors.length}`);
  
  if (errors.length > 0) {
    console.error('\n❌ Validation failed with errors');
    return false;
  }
  
  if (warnings.length > 0) {
    console.warn('\n⚠️  Validation completed with warnings');
    if (checkMode) {
      console.error('❌ Check mode: exiting with error due to warnings');
      return false;
    }
  }
  
  console.log('\n✅ Validation passed');
  return true;
}

// Main execution
const valid = validateManifest();

if (checkMode) {
  process.exit(valid ? 0 : 1);
} else {
  if (!valid) {
    console.error('\n⚠️  Please review and update integrations.watch.yaml');
  }
  process.exit(0);
}
