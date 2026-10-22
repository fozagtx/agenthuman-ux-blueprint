-- MCP kit: OAuth clients, connections, codes, tokens, audit log, rate limits.
CREATE TABLE oauth_clients (
  id text PRIMARY KEY,
  name text NOT NULL,
  redirect_uris text[] NOT NULL,
  metadata jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX connections_user_id_idx ON connections (user_id);

CREATE TABLE oauth_authorization_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id text NOT NULL,
  client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  state text,
  code_challenge text NOT NULL,
  scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
  resource text,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX oauth_authorization_requests_request_id_idx
  ON oauth_authorization_requests (request_id);

CREATE TABLE oauth_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash text NOT NULL,
  client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  connection_id uuid NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  code_challenge text NOT NULL,
  scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
  resource text,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX oauth_codes_code_hash_idx ON oauth_codes (code_hash);

CREATE TABLE oauth_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  connection_id uuid NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  client_id text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  hash text NOT NULL,
  type text NOT NULL CHECK (type IN ('access', 'refresh')),
  family_id uuid NOT NULL,
  scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
  resource text,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX oauth_tokens_hash_idx ON oauth_tokens (hash);
CREATE INDEX oauth_tokens_family_id_idx ON oauth_tokens (family_id);

CREATE TABLE tool_activity (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  connection_id uuid NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  tool text NOT NULL,
  args_json jsonb NOT NULL,
  decision text NOT NULL,
  error text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tool_activity_connection_id_idx ON tool_activity (connection_id);

CREATE TABLE rate_limits (
  key text PRIMARY KEY,
  window_started_at timestamptz NOT NULL,
  count integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL
);
