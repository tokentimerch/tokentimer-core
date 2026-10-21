// Verifies that what the wizard set up is actually monitored. Inputs are live
// reads (summary, the asset, its alert state), never session flags.

export const CHECK_STATUS = { PASS: 'pass', FAIL: 'fail', WARN: 'warn' };

function check(id, status, label, detail) {
  return { id, status, label, detail: detail || null };
}

export const NO_CERTIFICATE_YET =
  'No certificate could be read yet. TokenTimer keeps checking it.';

const expiryDay = m => String(m.certificateExpiresAt).slice(0, 10);

// Several websites: one line each. The step passes when at least one has a
// readable certificate, because a batch can mix reachable and unreachable
// sites and the reachable ones are already protected. With none readable it
// fails. A site that is not readable yet is a follow-up, not a failure.
function websiteChecks(monitors, unlisted) {
  const checks = [];
  for (const m of monitors) {
    if (!m.certificateExpiresAt) {
      checks.push(
        check(
          `certificate:${m.url}`,
          CHECK_STATUS.WARN,
          m.url,
          NO_CERTIFICATE_YET
        )
      );
      continue;
    }
    checks.push(
      check(
        `certificate:${m.url}`,
        CHECK_STATUS.PASS,
        m.url,
        `Certificate was read from the website. Expires ${expiryDay(m)}`
      )
    );
    if (!m.tokenId) {
      checks.push(
        check(
          `asset:${m.url}`,
          CHECK_STATUS.FAIL,
          `${m.url} is tracked as an asset`,
          'The certificate was read but no asset was created for it, so no alert can be sent. Re-add the website to retry.'
        )
      );
    }
  }
  if (!monitors.some(m => m.certificateExpiresAt)) {
    checks.push(
      check(
        'certificate',
        CHECK_STATUS.FAIL,
        'Certificate was read from a website',
        'TokenTimer could not read a certificate from any of these addresses. Check that they are reachable over HTTPS from this deployment.'
      )
    );
  }
  if (unlisted > 0) {
    checks.push(
      check(
        'unlisted',
        CHECK_STATUS.WARN,
        `${unlisted} more ${unlisted === 1 ? 'website is' : 'websites are'} not listed here`,
        'Open the Monitoring page to see the rest.'
      )
    );
  }
  return checks;
}

/**
 * @param {object} input
 * @param {'monitor_https'|'track_asset'} input.goal
 * @param {object|null} input.monitor  summary.monitors item for the URL
 * @param {object[]} [input.monitors]  every monitor of this session; wins over `monitor`
 * @param {number} [input.unlistedMonitors] session monitors the summary could not list
 * @param {object|null} input.token    asset incl. alert_state (GET /api/tokens/:id)
 * @param {object|null} input.summary  verified workspace summary
 */
export function evaluateVerification({
  goal,
  monitor: legacyMonitor,
  monitors,
  unlistedMonitors = 0,
  token,
  summary,
  infrastructure,
}) {
  const checks = [];

  const sessionMonitors = Array.isArray(monitors)
    ? monitors
    : legacyMonitor
      ? [legacyMonitor]
      : [];
  if (
    goal === 'monitor_https' &&
    (sessionMonitors.length > 1 || unlistedMonitors > 0)
  ) {
    checks.push(...websiteChecks(sessionMonitors, unlistedMonitors));
  } else if (goal === 'monitor_https') {
    const monitor = sessionMonitors[0] || null;
    if (!monitor) {
      checks.push(
        check(
          'monitor',
          CHECK_STATUS.FAIL,
          'Website is being monitored',
          'The monitor was not found. It may have been removed.'
        )
      );
    } else if (!monitor.certificateExpiresAt) {
      checks.push(
        check(
          'certificate',
          CHECK_STATUS.FAIL,
          'Certificate was read from the website',
          'TokenTimer could not read a certificate from this address. Check that it is reachable over HTTPS from this deployment.'
        )
      );
    } else {
      checks.push(
        check(
          'certificate',
          CHECK_STATUS.PASS,
          'Certificate was read from the website',
          `Expires ${String(monitor.certificateExpiresAt).slice(0, 10)}`
        )
      );
    }
    if (monitor && monitor.certificateExpiresAt && !monitor.tokenId) {
      checks.push(
        check(
          'asset',
          CHECK_STATUS.FAIL,
          'Certificate is tracked as an asset',
          'The certificate was read but no asset was created for it, so no alert can be sent. Re-add the website to retry.'
        )
      );
    }
  }

  if (goal === 'track_asset') {
    checks.push(
      token
        ? check('asset', CHECK_STATUS.PASS, 'Asset exists')
        : check(
            'asset',
            CHECK_STATUS.FAIL,
            'Asset exists',
            'The asset was not found. It may have been removed.'
          )
    );
  }

  // Goals that bring in assets without a single known id (imports) or that
  // are about alerting: the soonest-expiring asset is the sample to check.
  if (
    goal === 'import_file' ||
    goal === 'import_integration' ||
    goal === 'alerting'
  ) {
    const total = summary?.assets?.total || 0;
    if (goal !== 'alerting') {
      checks.push(
        total > 0
          ? check(
              'assets',
              CHECK_STATUS.PASS,
              'Assets are in this workspace',
              `${total} in total`
            )
          : check(
              'assets',
              CHECK_STATUS.FAIL,
              'Assets are in this workspace',
              'No assets were found. The import may have been cancelled or removed.'
            )
      );
    } else if (total === 0) {
      checks.push(
        check(
          'assets',
          CHECK_STATUS.WARN,
          'There are no assets to alert on yet',
          'Alerts apply once you add or import assets.'
        )
      );
    }
  }

  if (goal && goal.startsWith('certops_')) {
    const certops = summary?.certops;
    if (!certops || certops === 'unknown') {
      checks.push(
        check(
          'certops',
          CHECK_STATUS.WARN,
          'Agent status could not be read',
          'You may not have permission to see agents, or certificate management is off.'
        )
      );
    } else {
      const live = certops.agents?.live || 0;
      const clusters = certops.controllers?.clusters || [];
      if (goal === 'certops_observe' && infrastructure === 'kubernetes') {
        // The controller is not an agent: it is connected once it has reported.
        checks.push(
          clusters.length > 0
            ? check(
                'controller',
                CHECK_STATUS.PASS,
                'The Kubernetes controller is reporting',
                `Cluster ${clusters[0].clusterId}`
              )
            : check(
                'controller',
                CHECK_STATUS.FAIL,
                'The Kubernetes controller is reporting',
                'No cluster has reported yet. Check the controller pod logs and that the token matches the cluster id.'
              )
        );
      } else {
        checks.push(
          live > 0
            ? check(
                'agent',
                CHECK_STATUS.PASS,
                'An agent is connected',
                `${live} live`
              )
            : check(
                'agent',
                CHECK_STATUS.FAIL,
                'An agent is connected',
                'No agent has checked in recently. Check the service on the server.'
              )
        );
      }
      const certs = certops.certificates?.total || 0;
      checks.push(
        certs > 0
          ? check(
              'certificates',
              CHECK_STATUS.PASS,
              'Certificates are being reported',
              `${certs} in the inventory`
            )
          : check(
              'certificates',
              CHECK_STATUS.WARN,
              'No certificates reported yet',
              'Discovery runs about hourly. The folders must contain a readable PEM certificate.'
            )
      );
      if (goal === 'certops_adcs') {
        const { adcs } = certops;
        const ready =
          (adcs?.issuers || []).some(i => i.confirmed && i.safe) &&
          (adcs?.profiles || 0) > 0;
        // The server sees the issuer and profile, never an enrollment.
        checks.push(
          check(
            'adcs',
            CHECK_STATUS.WARN,
            ready
              ? 'Issuer and profile exist, enrollment is not verified'
              : 'The AD CS issuer or profile is missing',
            'Attach the profile to a certificate and confirm the first enrollment in Certificate Management. This guided setup has not been verified through a real enrollment yet.'
          )
        );
      }
      if (goal === 'certops_vault') {
        // Never report a candidate feature as working without evidence.
        checks.push(
          certops.distribution?.verified
            ? check(
                'distribution',
                CHECK_STATUS.PASS,
                'Distribution verified by a rollout'
              )
            : check(
                'distribution',
                CHECK_STATUS.WARN,
                'Distribution is not verified',
                'Configuration may be prepared, but no rollout has been verified yet.'
              )
        );
      }
    }
  }

  const channels = token?.alert_state?.eligibility?.eligible_channels;
  if (token) {
    if (Array.isArray(channels) && channels.length > 0) {
      checks.push(
        check(
          'routing',
          CHECK_STATUS.PASS,
          'Alerts have a recipient',
          `Will notify through: ${channels.join(', ')}`
        )
      );
    } else {
      checks.push(
        check(
          'routing',
          CHECK_STATUS.FAIL,
          'Alerts have a recipient',
          'No alert channel would be used for this asset. Make sure the default contact group has an email recipient and that email alerts are switched on in workspace preferences.'
        )
      );
    }
  }

  const smtp = summary?.alerts?.smtpConfigured;
  if (smtp === true) {
    checks.push(check('smtp', CHECK_STATUS.PASS, 'Email delivery is set up'));
  } else if (smtp === false) {
    checks.push(
      check(
        'smtp',
        CHECK_STATUS.WARN,
        'Email delivery is not set up yet',
        'Alerts are routed but cannot be emailed until an administrator configures SMTP.'
      )
    );
  } else {
    checks.push(
      check(
        'smtp',
        CHECK_STATUS.WARN,
        'Email delivery could not be checked',
        'Ask an administrator to confirm SMTP is configured.'
      )
    );
  }

  const failed = checks.filter(c => c.status === CHECK_STATUS.FAIL);
  return {
    checks,
    // Delivery warnings are follow-ups, not failures of the objective.
    ok: failed.length === 0 && checks.some(c => c.status === CHECK_STATUS.PASS),
    needsDeliverySetup: checks.some(
      c => c.id === 'smtp' && c.status === CHECK_STATUS.WARN
    ),
  };
}
