CREATE TABLE IF NOT EXISTS operator_oauth_clients (
  client_id TEXT PRIMARY KEY,
  metadata JSONB NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('registration', 'metadata')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS operator_oauth_authorizations (
  id UUID PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES operator_oauth_clients(client_id),
  client_metadata JSONB NOT NULL,
  resource TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  state TEXT,
  code_challenge TEXT NOT NULL,
  browser_nonce_hash TEXT NOT NULL,
  consent_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  consent_session_hash TEXT,
  connection_id UUID REFERENCES operator_connections(id) ON DELETE CASCADE,
  decision TEXT NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending', 'approved', 'denied')),
  code_hash TEXT UNIQUE,
  code_expires_at TIMESTAMPTZ,
  code_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS operator_oauth_grants (
  id UUID PRIMARY KEY,
  connection_id UUID NOT NULL UNIQUE REFERENCES operator_connections(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES operator_oauth_clients(client_id),
  resource TEXT NOT NULL,
  generation_count INTEGER NOT NULL DEFAULT 0 CHECK (generation_count BETWEEN 0 AND 10000),
  refresh_allowed BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS operator_oauth_tokens (
  lookup_prefix TEXT PRIMARY KEY,
  credential_hash TEXT NOT NULL UNIQUE,
  grant_id UUID NOT NULL REFERENCES operator_oauth_grants(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_operator_oauth_authorization_expiry ON operator_oauth_authorizations(expires_at);
CREATE INDEX IF NOT EXISTS idx_operator_oauth_token_grant ON operator_oauth_tokens(grant_id);
CREATE INDEX IF NOT EXISTS idx_operator_oauth_token_expiry ON operator_oauth_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_operator_oauth_grant_expiry ON operator_oauth_grants(expires_at);
CREATE INDEX IF NOT EXISTS idx_operator_oauth_client_expiry ON operator_oauth_clients(expires_at);
