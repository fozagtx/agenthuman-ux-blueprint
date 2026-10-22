-- MCP kit: cache for Client ID Metadata Documents (CIMD clients such as ChatGPT).
ALTER TABLE oauth_clients ADD COLUMN metadata_fetched_at timestamptz;
