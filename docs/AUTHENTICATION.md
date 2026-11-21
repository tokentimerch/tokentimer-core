# TokenTimer Authentication Model

## Initial Setup

### Step 1: Set Admin Credentials

Before first startup, set environment variables:

```bash
ADMIN_EMAIL=admin@company.com
ADMIN_PASSWORD=YourSecurePassword123!
ADMIN_NAME=Administrator
```

### Step 2: Start TokenTimer

```bash
docker compose up -d
```

On first startup, TokenTimer will:

1. Detect no users exist
2. Create admin user with provided credentials (`is_admin = true`, system admin)
3. Create the shared **Default workspace** and add the admin as workspace admin
4. Log admin credentials (email shown, password hidden)

On subsequent user registration or first login (when not joining via invitation), users without workspace membership are placed on the installation **Default workspace**:

- If **Default workspace** already exists, they join it.
- If exactly one workspace exists (legacy installs), they join that workspace.
- Otherwise a new **Default workspace** is created.
- Workspace role: **admin** (workspace owner) only for the user who **creates** a new Default workspace; **workspace_manager** for everyone who joins an existing Default workspace (including system admins).

## Single sign-on

Core supports one active OIDC and one active SAML provider at the same time. A system administrator can choose **Set up single sign-on for my team** in the setup guide or open **System Settings → Single Sign-On (SSO)** to manage providers and policies. Use public HTTPS origins for `API_URL` and `APP_URL`. Route both `/auth` and `/api` to the API. Keep a verified local administrator for recovery and test each configured provider in a private window.

- **OIDC.** Register the exact `/auth/oidc/<slug>/callback` URL on a confidential authorization-code client. Enable PKCE S256, request `openid profile email`, and enter the issuer, client ID and client secret. Register the dashboard login URL for post-logout redirects if supported.
- **SAML.** Register the SP entity ID and POST ACS shown in the wizard. Paste the IdP metadata XML or supply its URL. The IdP must send a signed assertion with a stable NameID and an email attribute. Once the provider is enabled and ready, get SP metadata at `/auth/saml/<slug>/metadata`. Keep `validate_in_response_to=always` to bind each response to the browser that started sign-in. `ifPresent` also accepts unsolicited sign-ins, and `never` disables request correlation. Application logout ends the local session.
- **Group mappings.** In **Single Sign-On (SSO)**, map a group to Viewer or Workspace Manager for a workspace, or grant System Admin globally. Preview a sample claim in the provider editor’s Group mapping simulator. Removing a mapping revokes unmatched SSO-managed workspace memberships at the next sign-in only with strict sync enabled. Remove a System Admin grant explicitly in **Workspaces → Members**.
- **Accounts and recovery.** The provider slug and subject identify a returning user. Keep the slug stable. Local-account email linking is disabled by default. If enabled, OIDC requires an IdP-verified email. SAML trusts the signed assertion for linking, so enable it only when the IdP controls the email claim. To accept a pending workspace invitation during SSO sign-in, the IdP must send the exact invited email and its verification claim. New SSO users otherwise follow the installation’s existing workspace and group policies. Test the expected access with an ordinary user and the local recovery administrator.
- **Changing providers.** Create a new provider to change the OIDC issuer after accounts have linked. Disable the current provider of that protocol before enabling its replacement. If an adopted database has more than one enabled provider of the same protocol, Core suspends that protocol until a local recovery administrator selects which provider to keep in **SSO Providers**. Selection preserves the stored settings and identities of the disabled providers.
- **Retiring providers.** Preview access changes in the provider editor. To delete a used provider, keep a working local administrator and explicitly choose how to handle provider-managed memberships and linked identities. Existing manually managed memberships stay in place.

See [provider configuration notes](#provider-configuration-notes) and [deployment, key rotation and rollback](CONFIGURATION.md#single-sign-on).

### Provider configuration notes

**Keycloak is the reference integration.** For OIDC, use the realm issuer `https://idp.example.com/realms/<realm>`, enable client authentication and Standard flow, and register the displayed redirect URI. For SAML, create a SAML client with the displayed SP entity ID and POST ACS, enable signed assertions, and import the SAML IdP metadata with the realm signing certificate. Map email and a stable NameID for the test user. Verify the resulting TokenTimer account, workspace and logout in a fresh browser session.

| Provider | Configuration notes |
| --- | --- |
| authentik, ZITADEL, GitLab CE or GitLab.com | Use Generic OIDC. For authentik, use the application issuer including its slug and trailing slash. For ZITADEL use the instance issuer and a Web application. For GitLab register an OAuth application with the instance root as issuer and the `openid profile email` scopes. The wizard includes endpoint hints for all three. |
| Microsoft Entra ID | Use a tenant-specific v2 issuer for OIDC. For SAML, configure the displayed reply URL and identifier, and map the emitted email/name attributes. |
| Okta | Use the issuer for the assigned authorization server and assign the user to the app. For SAML, copy the ACS and audience from TokenTimer and supply the Okta signing certificate. |
| Auth0, Google Workspace, Amazon Cognito | Use a confidential web client. Preserve the Auth0 discovery issuer, including its trailing slash. Google Workspace standard OIDC does not emit group membership. Cognito uses the user-pool issuer for discovery and its hosted domain for interactive login. |
| AD FS, SimpleSAMLphp | Use Generic SAML. Configure the relying party with the displayed POST ACS and entity ID, map a stable NameID and email, then supply the IdP metadata and test a signed assertion. |

The wizard's connectivity check tests provider configuration. Qualify each deployment by signing in, checking the user's claims and access, and logging out.

## System admin vs workspace owner

TokenTimer separates **installation-wide administration** from **workspace ownership**. They use different database fields and are granted through different paths.

| | System admin | Workspace owner |
|--|--------------|-----------------|
| **Stored as** | `users.is_admin = TRUE` | `workspace_memberships.role = 'admin'` |
| **Scope** | Whole installation (System Settings, SMTP, grant/revoke system admin, SSO provider administration) | One workspace (rename, delete workspace, org-scoped audit for that workspace) |
| **Dashboard** | **System Settings** nav (when `session.user.isAdmin`) | **Workspaces** owner actions (rename, delete) |
| **How to grant** | **Workspaces → Members → System admin** toggle (system admins only), or SSO `admin` group mapping | Automatic when **creating** a workspace; not assignable from Members tab |
| **How many** | Multiple system admins supported | One owner per workspace in normal operation (creator at provision time) |

**Important:** Granting system admin to a second user does **not** make them workspace owner on the shared Default workspace. They remain **manager** there unless they separately created that workspace.

### Default workspace on join

When a user without membership logs in (local or SSO):

1. Pending invitations are accepted first.
2. Otherwise they join the installation **Default workspace** (or the sole legacy workspace).
3. Join role is always **workspace_manager** when Default already exists, even if `users.is_admin = TRUE`.
4. Join role is **admin** only when this login creates a brand-new Default workspace (empty install).

### What you cannot do from the UI

- **Invite** someone as workspace owner (`admin` membership is rejected by the API).
- **Promote** an existing member to workspace owner via the role dropdown (only Viewer and Manager).
- **Demote or remove** a workspace owner via the Members tab (API blocks changes to `admin` membership rows).

To add another workspace owner today you would need a direct database change; the product intentionally supports a single owner per workspace until [v1.0.0](../ROADMAP.md#v100----rbac-and-role-model-cleanup) adds co-owner management.

### Granting a second system admin

A system admin can open **Workspaces → Members**, find any member, and enable **System admin**. That sets `users.is_admin = TRUE` only. The member keeps their current workspace role (typically **manager** on Default). They gain System Settings and admin API access immediately (session reloads `is_admin` on each request).

The last system admin cannot demote themselves.

### Step 3: Remove Admin Password

After first login, remove `ADMIN_PASSWORD` from `.env`:

```bash
# Remove or comment out ADMIN_PASSWORD
# ADMIN_PASSWORD=...
```

Restart services:

```bash
docker compose restart
```

## Adding Users (Invitation Flow)

### For Admins

1. Login to Dashboard
2. Go to **Workspaces** > select a workspace > **Members**
3. Invite by email with role **Viewer** or **Manager**
4. To grant **system admin** (installation-wide access to System Settings and admin APIs), toggle **System admin** on an existing member. Only current system admins see this control.

**System admin** (`users.is_admin`) is installation-wide. **Workspace manager** controls day-to-day workspace operations (invites, tokens, alert settings). Workspace **owner** (`admin` membership role) is assigned automatically when a workspace is created and is not changed from the Members tab.

### For Invited Users

1. Receive invitation email (or link from admin)
2. Click invitation link: `https://your-instance.com/register?token=<token>&email=<email>`
3. Set password (see [Password requirements](#password-requirements) below)
4. Account created and automatically added to workspace with assigned role

### Password requirements

Enforced server-side on invitation acceptance, password reset, and password
change. All five rules are mandatory and none of them are configurable:

- at least **12** characters
- at least one **lowercase** letter
- at least one **uppercase** letter
- at least one **number**
- at least one **special character** (`!@#$%^&*()_+-=[]{};':"\|,.<>/?`)

Password reset additionally rejects passwords that *start with* a common
sequence (`password`, `123456`, `qwerty`, `admin`, `letmein`, `welcome`,
`monkey`, `dragon`), so a password can satisfy all five rules above and still be
refused on that route.

A rejected password returns `400`. On invitation acceptance and password reset
the body carries `code: "VALIDATION_ERROR"`, `error` set to the first failing
rule, and `details` listing every failing rule. Password *change*
(`POST /api/account/change-password`) returns only `error`, set to a single fixed
message listing the rules, with no `code` or `details`.

## API Endpoints

### Admin Bootstrap (Automatic on First Start)

Not an HTTP endpoint. Runs internally on API startup (`auth/bootstrap.js`):
- Creates admin if no users exist in the database
- Reads `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME` from env
- Skipped if `DISABLE_ADMIN_BOOTSTRAP=true`
- Skipped if any user already exists

### Add Member / Invite User (Admin or Manager)

Returns `403 { code: "MANUAL_INVITES_DISABLED" }` when `DISABLE_MANUAL_INVITES=true`.
Use this to lock down user provisioning to your identity provider (SSO/IDM)
only; already-pending invitations and their acceptance via
`POST /auth/register` are unaffected, as is listing or cancelling existing
invitations.

```
POST /api/v1/workspaces/:id/members
Content-Type: application/json

{
  "email": "user@company.com",
  "role": "workspace_manager"
}
```

An existing verified local account receives access immediately. Other recipients receive a pending invitation. An SSO user redeems it by signing in with proof of the exact invited address. To change a current SSO member’s role, use the member ID endpoint below.

### List Members

```
GET /api/v1/workspaces/:id/members
```

### Change Member Role (Admin or Manager)

```
PATCH /api/v1/workspaces/:id/members/:userId
Content-Type: application/json

{
  "role": "workspace_manager"
}
```

Allowed roles: `viewer`, `workspace_manager` only. The workspace owner role (`admin` membership) is not assignable via this endpoint.

### Grant or Revoke System Admin (System Admin only)

```
PATCH /api/admin/users/:userId/system-admin
Content-Type: application/json

{
  "is_admin": true
}
```

Sets `users.is_admin` (installation-wide). Requires an authenticated system admin. The last system admin cannot demote themselves.

### Remove Member (Admin or Manager)

```
DELETE /api/v1/workspaces/:id/members/:userId
```

### Accept Invitation (Public)

Cookie-session clients must `GET /api/csrf-token` and send the JSON
`csrfToken` as `X-CSRF-Token`. Do not copy the cookie. Cookie names are
`x-csrf-token` (default) or `__Host-psifi.x-csrf-token` (production +
Secure + no `SESSION_COOKIE_DOMAIN`). The cookie is an httpOnly HMAC, not
the header token. A missing header is 403 `EBADCSRFTOKEN`. The dashboard
already does this.

```
GET /api/csrf-token
```

Use the JSON `csrfToken` on the register and login POSTs below.

```
POST /auth/register
Content-Type: application/json
X-CSRF-Token: <csrfToken>

{
  "token": "invitation-token-here",
  "email": "user@company.com",
  "password": "NewSecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

### Login

```
POST /auth/login
Content-Type: application/json
X-CSRF-Token: <csrfToken>

{
  "email": "admin@company.com",
  "password": "YourPassword123!"
}
```

### Logout

```
POST /auth/logout
```

Logout does not require `X-CSRF-Token`.

## Authentication Features

| Feature | Status |
|---|---|
| Admin bootstrap (env vars) | Enabled by default |
| User invitations (admin or manager) | Enabled by default; blockable with `DISABLE_MANUAL_INVITES=true` |
| Local email/password auth | Always available (not configurable) |
| Two-factor authentication (TOTP) | Always available, opt-in per user |
| CSRF protection | Always on (not configurable), including development (`NODE_ENV=test` still skips it). Cookie-session clients must send `X-CSRF-Token` from `GET /api/csrf-token` on mutating `/api` and `/auth` routes except logout. Cookie names are `x-csrf-token` (default) or `__Host-psifi.x-csrf-token` (production + Secure + no `SESSION_COOKIE_DOMAIN`). Do not copy the cookie; it is an httpOnly HMAC. Missing header is 403 `EBADCSRFTOKEN`. |
| Email verification | Enforced for local accounts only (`auth_method = 'local'`); not env-configurable |

## Configuration

### Environment Variables

```bash
# Required for first startup
ADMIN_EMAIL=admin@company.com
ADMIN_PASSWORD=SecurePassword123!
ADMIN_NAME=Administrator

# Optional: SMTP (for invitation emails and password reset)
SMTP_HOST=smtp.company.com
SMTP_USER=tokentimer@company.com
SMTP_PASS=...

```

### Helm

When deploying via the Helm chart, `config.adminEmail` is required. The admin
password is auto-generated if not provided (retrieve it from the Kubernetes
secret after install). See [deploy/helm/README.md](../deploy/helm/README.md).

### Auth tuning

There is no auth-tuning environment surface in Core today. The following
variables are parsed into an internal config object but **no code reads the
result**, so setting any of them has no effect:

`LOCAL_AUTH_ENABLED`, `REQUIRE_EMAIL_VERIFICATION`, `TWO_FACTOR_ENABLED`,
`SESSION_MAX_AGE`, `MIN_PASSWORD_LENGTH`, `REQUIRE_UPPERCASE`,
`REQUIRE_NUMBERS`, `CSRF_ENABLED`.

The actual, non-configurable behavior is:

| Behavior | Actual value | Where |
|---|---|---|
| Session cookie lifetime | 2 hours, `rolling` (renewed on activity) | `apps/api/session-cookie-options.js` |
| CSRF protection | Always on in development and production (skipped only when `NODE_ENV=test`). Double-submit cookie on `/api` and `/auth`. Cookie names `x-csrf-token` or `__Host-psifi.x-csrf-token`. Exempt: logout, worker-to-API bearer (`WORKER_API_KEY`), and CertOps machine-token routes. Missing header is 403 `EBADCSRFTOKEN`. | `apps/api/index.js`, `apps/api/middleware/csrf-exempt.js` |
| Local email/password auth | Always available | `apps/api/routes/auth.js` |
| Two-factor (TOTP) | Always available, opt-in per user | `apps/api/routes/auth.js` |
| Password rules | Fixed 5 rules, see [Password requirements](#password-requirements) | `apps/api/routes/auth.js` |

To change any of these today you must change code. Do not document or promise
these variables to operators.

## Security Considerations

**Advantages**:

- No public registration attack surface
- Admin controls all access via invitations
- Suitable for regulated environments (HIPAA, SOC2, ISO 27001)
- No email service required for basic setup (admin shares invite links manually)
- Full audit trail of who invited whom

**Requirements**:

- Admin must securely share invitation links if SMTP is not configured
- Invitation tokens never expire; cancel unused invitations instead of relying on a timeout
- Admin password should be strong (see [Password requirements](#password-requirements))
- `ADMIN_PASSWORD` should be removed from env after bootstrap

## Best Practices

1. **Secure Admin Bootstrap**:
   - Use strong `ADMIN_PASSWORD`
   - Remove `ADMIN_PASSWORD` from env after first login
   - Use a secrets manager or Helm `existingSecret` for credentials

2. **Invitation Management**:
   - Invite users with appropriate roles (viewer by default)
   - Send invitation links via secure channel
   - Cancel invitations you no longer expect to be accepted: invitation tokens
     **never expire** (`workspace_invitations` has no `expires_at` column), so a
     leaked link stays redeemable until it is accepted or cancelled via
     `DELETE /api/v1/workspaces/:id/invitations/:invitationId`
   - Review [workspace membership audit events](audit-events.md#workspaces-and-membership) for invitation history

3. **Two-Factor Authentication**:
   - Encourage all users to enable 2FA
   - Admin can enforce 2FA organization-wide (planned)

## FAQ

### Q: Can I disable admin bootstrap and create users manually?

**A**: Yes, set `DISABLE_ADMIN_BOOTSTRAP=true`. Then create users via SQL:

```sql
INSERT INTO users (email, password_hash, display_name, auth_method, email_verified)
VALUES ('admin@company.com', '$2b$12$...', 'Admin', 'local', TRUE);
```

### Q: Can users reset their passwords?

**A**: Only if SMTP is configured. Otherwise, admin must reset via database or re-invite the user.

### Q: What if admin forgets password?

**A**: Bootstrap only runs when no users exist, so setting `ADMIN_PASSWORD` again won't help. Options:

1. Use the password reset flow (requires SMTP to be configured)
2. Reset via database:
   ```bash
   # Generate a bcrypt hash (cost 12)
   node -e "require('bcryptjs').hash('NewPassword123!',12).then(h=>console.log(h))"
   ```
   ```sql
   UPDATE users SET password_hash = '<hash from above>' WHERE email = 'admin@company.com';
   ```

### Q: Can invited users invite others?

**A**: Admins and workspace managers can invite with viewer or manager roles. System admins can grant or revoke installation-wide admin (`is_admin`) from **Workspaces → Members** using the **System admin** toggle.

### Q: Does system admin imply workspace owner on Default?

**A**: No. System admin (`users.is_admin`) and workspace owner (`workspace_memberships.role = 'admin'`) are independent. SSO or manual system-admin grants do not promote users to workspace owner. Users joining an existing Default workspace always get **workspace_manager**, including system admins. Only the user who creates Default on an empty install becomes workspace owner automatically.

System-admin expansion (manual toggle, SSO admin grant, or login provisioning) adds missing `workspace_manager` rows on every workspace and may raise `viewer` to `workspace_manager` where needed. It never downgrades an existing workspace `admin` membership.

### Q: Can I make a second workspace owner on Default?

**A**: Not through the dashboard or public API today. Workspace owner is assigned at workspace creation only. You can grant a second user **system admin** from **Workspaces → Members**, which gives installation-wide settings access but not workspace-owner powers (delete workspace, etc.). Multiple workspace owners per workspace are planned for [v1.0.0](../ROADMAP.md#v100----rbac-and-role-model-cleanup).

### Q: Who can transfer tokens between workspaces?

**A**: Not owner-only. `POST` transfer requires a membership in **both** the
source and target workspace, where each membership is `admin` **or**
`workspace_manager`. If either side is `workspace_manager`, the caller must also
hold at least **2** workspace memberships in total. Otherwise the request is
rejected with `403 FORBIDDEN`. The move is transactional and audited as
`TOKENS_TRANSFERRED_BETWEEN_WORKSPACES`.

Linked domain monitors and managed certificates move with the token, together
with their associated targets, instances, jobs, and evidence. Destination
identity or idempotency conflicts can block the transfer. Renewal profiles stay
in the source workspace, and transferred certificate/target profile links are
cleared. Agent enrollment and private keys are not transferred.

Contact-group assignments keep an ID already present in the destination;
otherwise they are matched by case-insensitive group name. Unmatched assignments
are removed. Check destination recipients and configure renewal profiles and an
eligible agent before relying on alerts or automatic renewal.

## Contact

- General: support@tokentimer.ch
- Sales: sales@tokentimer.ch
