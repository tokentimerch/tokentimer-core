// Verifies that what the wizard set up is actually monitored. Inputs are live
// reads (summary, the asset, its alert state), never session flags.

export const CHECK_STATUS = { PASS: 'pass', FAIL: 'fail', WARN: 'warn' };

function check(id, status, label, detail) {
  return { id, status, label, detail: detail || null };
}

/**
 * @param {object} input
 * @param {'monitor_https'|'track_asset'} input.goal
 * @param {object|null} input.monitor  summary.monitors item for the URL
 * @param {object|null} input.token    asset incl. alert_state (GET /api/tokens/:id)
 * @param {object|null} input.summary  verified workspace summary
 */
export function evaluateVerification({ goal, monitor, token, summary }) {
  const checks = [];

  if (goal === 'monitor_https') {
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
          'No alert channel would be used for this asset. Make sure the default contact group has an email recipient.'
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
