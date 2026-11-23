# Audit event catalog

Audit rows identify the action, timestamp, actor, subject, target, channel, workspace, and event details. A background process may have no user actor. For UUID-backed resources, look in `workspace_id` or metadata because `target_id` stores integers. Historical rows retain the metadata available when they were written. See [CertOps audit events](certops/audit-events.md) for certificate and agent activity.

Open **Audit** in the dashboard and select **This workspace** to include machine activity. Enter an action name in **Exact audit action** and press Enter, then search by an identifier such as the management period ID to narrow the results. CSV and JSON exports use the active filters. CSV includes separate actor and subject user ID columns so you can identify who made a change and whose account it affected.

## Authentication and account

- `REGISTRATION` records an account created through an invitation. Metadata includes `method` and `invited_role`.
- `LOGIN_SUCCESS` records the sign-in `method`. OIDC and SAML also record `provider_slug`. `LOGIN_SUCCESS_2FA` records the second `factor`.
- `LOGIN_FAILED` records a `reason`. Password failures against a known account include `email`. For SSO, use `method` and `provider_slug` to investigate failures that occur before an account is identified.
- `LOGOUT` records a session sign-out with `via`.
- `TWO_FACTOR_ENABLED` and `TWO_FACTOR_DISABLED` record `factor` and `via`. Disabling can come from account settings or password reset.
- `EMAIL_VERIFIED` and `EMAIL_VERIFICATION_RESENT` record the email-link `method`.
- `PASSWORD_RESET_REQUESTED` follows email delivery and records `method`. `PASSWORD_RESET_COMPLETED` includes `method` and `two_factor_reset`.
- `PASSWORD_CHANGED` records an authenticated password change with `via`.
- `SYSTEM_ADMIN_CHANGED` records the subject user's resulting `is_admin` flag.
- `ONBOARDING_STARTED`, `ONBOARDING_COMPLETED`, and `ONBOARDING_RESET` record the onboarding `flow`.

## Workspaces and membership

- `WORKSPACE_CREATED` records `name` and, for a default workspace, `kind`.
- `WORKSPACE_RENAMED` records `before.name` and `after.name`. `WORKSPACE_DELETED` records `name` and `workspaceId`.
- `MEMBER_INVITED_OR_UPDATED` records `role`, `email`, `workspace_name`, and `recipient_type`. `INVITE_EMAIL_SENT` confirms delivery was handed to the mail provider and records `role`, `email`, and `workspace_name`.
- `INVITATION_CANCELLED` records `email`, `role`, `workspace_name`, and `invitation_id`.
- `WORKSPACE_MEMBERSHIP_ACCEPTED` records `role` and, for automatic setup, `kind`.
- `MEMBER_ROLE_CHANGED` records `role` and `previous_role`. `MEMBER_REMOVED` records `removed_role` when a membership was deleted.
- `WORKSPACE_ALERT_SETTINGS_UPDATED` records `changed` and optional `contact_groups_changes`. Operator connections use `changed_fields` and can include `contact_group_id`.
- `ALERT_PREFS_UPDATED` records which account preference keys `changed`.

## Tokens, integrations, and monitors

- `TOKEN_CREATED` records `name`, `type`, and `category`. An operator inventory import records type and category with operator provenance.
- `TOKEN_UPDATED` records `fields` and optional `changes`, `name`, or `bulk`. Integration refreshes may include `reason`, `name`, `type`, `category`, `source`, `mount`, and `path`.
- `TOKEN_DELETED` records `name` and, when available, `reason`, `bulk`, `location`, or `provider`. An obsolete-token removal uses `reason: import_cleanup`.
- `TOKEN_IMPORTED` records `source`, `name`, `type`, `category`, and optional Vault `mount` and `path`. `TOKENS_IMPORTED` records `source`, `created_count`, `updated_count`, `error_count`, `deleted_count`, `detached_count` and optional `filtered_out_count` or an `errors` summary.
- `TOKENS_TRANSFERRED_BETWEEN_WORKSPACES` records `from_workspace_id`, `to_workspace_id`, `moved`, `dropped_contact_groups`, `moved_monitors`, and `moved_certificates`.
- `TOKENS_REASSIGNED_CONTACT_GROUP` records `from_group_id`, `to_group_id`, and `updated`.
- `INTEGRATION_SCAN` records `provider`, `itemsFound`, and, where applicable, `region` or `projectId`. `INTEGRATION_DETECT_REGIONS` records `provider` and `regionsFound`.
- `AUTO_SYNC_CREATED`, `AUTO_SYNC_UPDATED`, `AUTO_SYNC_DELETED`, and `AUTO_SYNC_TRIGGERED` record `config_id` and `provider`. Creation and updates include `enabled` and `frequency`. Updates can include `scan_version`.
- `AUTO_SYNC_COMPLETED` records `config_id`, `provider`, `status`, `items_scanned`, and `items_imported`. Optional fields include `created`, `updated`, `detached`, `deleted`, `errors`, `error`, and `import_errors`. `AUTO_SYNC_FAILED` records `config_id`, `provider`, `error`, `http_status`, and `consecutive_failures` when the configuration first enters the failed state.
- `DOMAIN_MONITOR_CREATED`, `DOMAIN_MONITOR_UPDATED`, `DOMAIN_MONITOR_DELETED`, and `DOMAIN_MONITOR_HEALTH_CHECK` record `monitor_id` and the HTTP(S) origin in `url`. Legacy malformed URLs can have a null origin. Create adds `ssl_detected`, update adds `fields_updated`, and a requested check adds `status`, `statusCode`, and `responseMs`.
- `DOMAIN_CHECKER_LOOKUP` records `domain`, `source`, `subfinder_all`, `results`, `partial`, `tools_succeeded`, `tools_failed`, and `truncated`.
- `DOMAIN_CHECKER_IMPORT` records `domain`, `source`, `submitted`, `imported`, `skipped`, `skipped_duplicate`, `skipped_invalid`, `skipped_unreachable`, `skipped_other_invalid`, `create_monitors`, `monitors_created`, and `monitors_existing`. When monitor creation is requested, it also records `monitor_check_interval`, `monitor_health_check_enabled`, `monitor_alert_after_failures`, and `monitor_contact_group_id`.

## Contacts and recipient verification

- `WORKSPACE_CONTACT_CREATED`, `WORKSPACE_CONTACT_UPDATED`, and `WORKSPACE_CONTACT_DELETED` record `contact_id`. Create and delete can include `phone_masked`. Updates record `fields_updated`.
- `RECIPIENT_VERIFICATION_INVITED`, `RECIPIENT_VERIFICATION_RESUBSCRIBE_REQUIRED`, `RECIPIENT_VERIFICATION_RATE_LIMITED`, and `RECIPIENT_VERIFICATION_REVOKED` record `contact_id` and `channel`. Invitation and resubscribe events include `destination_masked`. Rate-limit events include `code`.
- `RECIPIENT_WHATSAPP_CONFIRMED` records `channel` and `contact_id` for a verified inbound reply.
- `RECIPIENT_NOTIFICATION_TEST` records `contact_id` and the rate-limit `bucket` charged for a notification test. Look in the row's `channel` for the test channel.
- `WHATSAPP_TEST_SENT` and `WHATSAPP_TEST_SENT_TEMPLATE` record `phone_masked` and `message_sid`.
- `WHATSAPP_TEST_FAILED` and `WHATSAPP_TEST_FAILED_TEMPLATE` record `phone_masked`, `code`, and `error`. `WHATSAPP_TEST_RATE_LIMITED` records `phone_masked` and `retry_after_seconds`. `WHATSAPP_TEST_ERROR` records `error`.

## Alert delivery and incident actions

Delivery events include `alert_id` and `alert_key` when an alert exists. Workspace, token, and contact-group labels may also be available.

- `ALERT_QUEUED` records `daysUntil`, `threshold`, and `dueDate`. `ALERT_NOT_QUEUED_NO_CHANNEL` records `reason` and `threshold`.
- `ALERT_CHANNELS_UPDATED` records `from` and `to` channel sets.
- `ALERT_DELIVERY_DEFERRED` records `reason`, `threshold`, and `next_attempt_at`.
- `ALERT_SENT` records `days` and `channels`. `ALERT_SEND_FAILED` records `days`, `error`, and `attempts`. `ALERT_PARTIAL_SUCCESS` records `channel` and `errors`.
- `ALERT_RETRY_SCHEDULED` records `days`, `next_attempt_at`, and `channels_to_retry`. `ALERT_MANUAL_RETRY` records `reason`. `ALERTS_BULK_REQUEUED` records `updated` and `scope`.
- `ALERT_BLOCKED_MAX_ATTEMPTS` records `days` and the attempt count for each delivery channel. `ALERT_BLOCKED_WHATSAPP_ERROR` records `days` and has `whatsapp` in its `channel` column.
- `WEEKLY_DIGEST_SENT` records `contact_group_id`, `contact_group_name`, `tokens_count`, `channels`, and `week_start_date`.
- `WEBHOOK_RENAMED` records `previousName` and `name`.
- `PAGERDUTY_ACKNOWLEDGE_REQUESTED` and `PAGERDUTY_RESOLVE_REQUESTED` record `incident_id` when an operator queues the action. Resolution includes the operator's `reason`.

## Operator interface

- `OPERATOR_CONNECTION_CREATED`, `OPERATOR_CONNECTION_REVOKED`, and `OPERATOR_CONNECTION_CREDENTIAL_ROTATED` record `connection_id`. Manual connection events include `name`, `scopes`, `role_ceiling`, `credential_prefix`, `status`, and `expires_at`. OAuth events use `transport`, with `scopes` and `client_id` at creation or `reason` at revocation.
- `OPERATOR_ENROLLMENT_CREATED`, `OPERATOR_ENROLLMENT_REVOKED`, and `OPERATOR_ENROLLMENT_REDEEMED` record `enrollment_id`, `name`, `scopes`, `role_ceiling`, `connection_lifetime_days`, `status`, `expires_at`, and `connection_id` once available.
- `OPERATOR_RENEW_REQUESTED` and `OPERATOR_REQUEST_WITHDRAWN` record `via`, `connection_id`, `request_record_id`, `request_id`, `state`, `job_id`, and `replayed`.
- `OPERATOR_WRITES_ENABLED` and `OPERATOR_WRITES_DISABLED` record `previous` and `writes_enabled`. `OPERATOR_ISSUANCE_ENABLED` and `OPERATOR_ISSUANCE_DISABLED` record `previous` and `issuance_enabled`.

Operator-initiated inventory, contact, webhook, and membership events can also include `via`, `connection_id`, or `request_id` on their respective actions above.
