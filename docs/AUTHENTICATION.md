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
2. Create admin user with provided credentials
3. Create default workspace for admin
4. Log admin credentials (email shown, password hidden)

**Output**:

```
Creating initial admin user...
Initial admin user created successfully
   Email: admin@company.com
   Login at: http://localhost:5173/login

IMPORTANT: Remove ADMIN_PASSWORD from environment after first login!
   The admin can invite other users from the dashboard.
```

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
2. Go to Workspace Settings > Members
3. Click "Invite User"
4. Enter email address and role (Admin, Manager, or Viewer)
5. Send Invitation

TokenTimer generates an invitation link and (optionally) emails it to the user.

### For Invited Users

1. Receive invitation email (or link from admin)
2. Click invitation link: `https://your-instance.com/auth/verify-email/<token>`
3. Set password (min 8 characters, uppercase + number required)
4. Account created and automatically added to workspace with assigned role

## API Endpoints

### Admin Bootstrap (Automatic on First Start)

Not an HTTP endpoint. Runs internally on API startup (`auth/bootstrap.js`):
- Creates admin if no users exist in the database
- Reads `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME` from env
- Skipped if `DISABLE_ADMIN_BOOTSTRAP=true`
- Skipped if any user already exists

### Add Member / Invite User (Admin or Manager)

```
POST /api/v1/workspaces/:id/members
Content-Type: application/json

{
  "email": "user@company.com",
  "role": "workspace_manager"
}
```

If the email belongs to an existing user, they are added to the workspace directly.
If not, an invitation token is created and (optionally) emailed.

### List Members

```
GET /api/v1/workspaces/:id/members
```

### Remove Member (Admin or Manager)

```
DELETE /api/v1/workspaces/:id/members/:userId
```

### Accept Invitation (Public)

```
POST /auth/register
Content-Type: application/json

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

{
  "email": "admin@company.com",
  "password": "YourPassword123!"
}
```

### Logout

```
POST /auth/logout
```

## Authentication Features

| Feature | Status |
|---|---|
| Admin bootstrap (env vars) | Enabled by default |
| User invitations (admin only) | Always available |
| Local email/password auth | Enabled by default |
| Two-factor authentication (TOTP) | Enabled by default |
| CSRF protection | Enabled by default |
| Email verification | Configurable (`REQUIRE_EMAIL_VERIFICATION`) |

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

### Auth Tuning (all optional, sensible defaults)

```bash
LOCAL_AUTH_ENABLED=true
REQUIRE_EMAIL_VERIFICATION=true
TWO_FACTOR_ENABLED=true
SESSION_MAX_AGE=86400000          # 24h in ms
MIN_PASSWORD_LENGTH=8
REQUIRE_UPPERCASE=true
REQUIRE_NUMBERS=true
CSRF_ENABLED=true
```

## Security Considerations

**Advantages**:

- No public registration attack surface
- Admin controls all access via invitations
- Suitable for regulated environments (HIPAA, SOC2, ISO 27001)
- No email service required for basic setup (admin shares invite links manually)
- Full audit trail of who invited whom

**Requirements**:

- Admin must securely share invitation links if SMTP is not configured
- Admin password should be strong (min 8 chars, uppercase + number)
- `ADMIN_PASSWORD` should be removed from env after bootstrap

## Best Practices

1. **Secure Admin Bootstrap**:
   - Use strong `ADMIN_PASSWORD`
   - Remove `ADMIN_PASSWORD` from env after first login
   - Use a secrets manager or Helm `existingSecret` for credentials

2. **Invitation Management**:
   - Invite users with appropriate roles (viewer by default)
   - Send invitation links via secure channel
   - Set invitation expiry (default 7 days)
   - Review audit log for invitation history

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

**A**: Admins and workspace managers can invite. Viewers cannot. Note that invitations can only grant manager or viewer roles (admin role cannot be granted via invite).

## Contact

- General: support@tokentimer.ch
- Sales: sales@tokentimer.ch
