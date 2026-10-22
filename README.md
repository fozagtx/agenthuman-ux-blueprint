# agenthuman-ux

![A human finger touching a robotic finger](docs/assets/hero.png)

Let people use your project from Claude: they paste one URL, sign in, click
Allow, and Claude can call your tools on their behalf.

Repository: https://github.com/fozagtx/agenthuman-ux-blueprint

## What is it?

agenthuman-ux is a blueprint for a remote MCP server with OAuth sign-in. It is
a backend service (Node, Express, Postgres) extracted from StellaBox. It works
for any project where an AI should act for a signed-in person: a product, an
internal tool, a side project, or an existing API you want to expose.

It has two parts:

**The kit** (`src/mcp-kit/`) handles the protocol: the OAuth server Claude
signs in through, the consent screen, the `/mcp` endpoint, the favicon and
the audit log. It is required, and you should not need to edit it.

**Your project** (`src/project/`) is everything that changes per project:
branding, scopes, login, tables and tools. You edit all of it.

`src/app.ts` is the only file that connects the two. The kit never imports
your project's code. It receives branding, scopes, tools and login through
`createMcpKit()`. The only exception is its tables, which point at your
`users` table.

## How it works

```text
                  Claude
                    |
                    v
        POST /mcp (no token yet)
                    |
                    v
      401 + "sign in at this server"
                    |
                    v
   POST /register  ->  GET /authorize
                    |
                    v
      GET /connect  (your consent screen)
                    |
      signed in? -- no --> your login --+
                    |                   |
                   yes <----------------+
                    |
          Allow  /       \  Cancel
                v         v
        code sent       error=access_denied
        to Claude         sent to Claude
                |
                v
   POST /token  ->  access token (15 min)
                    refresh token (30 days, rotates)
                |
                v
   POST /mcp (Bearer token)  ->  your tools run as that user
```

Each Allow creates a **connection**: one user, one AI client, the scopes they
approved. Every token belongs to a connection, so revoking the connection cuts
the client off on its next call. Every tool call checks the token, the
connection, the scope and a rate limit of 120 calls per minute, then is
written to the audit log.

## Why use it?

- Claude, Claude Code and other MCP clients connect with only your URL. No API
  keys for users to copy.
- People approve exactly what the AI may do, see it on a consent screen, and
  can revoke it.
- The sign-in follows the MCP authorization spec: dynamic client registration,
  PKCE (S256), refresh-token rotation and token revocation.
- Codes and tokens are stored only as SHA-256 hashes.
- `/mcp` is stateless, so you can run several instances with no sticky sessions.
- Name, favicon and button colour are set in one file, or per deployment with
  env vars.
- An end-to-end script runs the full sign-in and tool flow (25 checks).

It has not yet been tested against the live Claude app; that needs a public
HTTPS URL (see [Connect it to Claude](#connect-it-to-claude)).

## Install

Requires Node 22 or newer, pnpm, and Postgres 16 (Docker or a local install).

```bash
git clone https://github.com/fozagtx/agenthuman-ux-blueprint.git my-project-mcp
cd my-project-mcp
pnpm install
cp .env.example .env
```

Then set `SESSION_SECRET` in `.env` (it must be at least 32 characters):

```bash
openssl rand -base64 32
```

## Quick start

Run it locally with the built-in dev login:

```bash
docker compose up -d        # Postgres on port 5434
pnpm db:migrate
pnpm dev                    # MCP server: http://localhost:4000/mcp
```

Check the full flow in a second terminal:

```bash
pnpm e2e
```

Try it in a browser without Claude:

```bash
npx @modelcontextprotocol/inspector
```

Choose transport "Streamable HTTP" and URL `http://localhost:4000/mcp`. The
inspector runs the sign-in; with `DEV_LOGIN=true` any email signs you in.

## Connect it to Claude

Claude calls your server from the internet, so it needs a public HTTPS URL.

1. Expose it. Locally:

   ```bash
   cloudflared tunnel --url http://localhost:4000
   ```

   Set `PUBLIC_API_URL` in `.env` to the tunnel URL and restart. In
   production, set it to your deployed domain.
2. In Claude, open **Settings → Connectors → Add custom connector** and paste
   `https://<your-domain>/mcp`.
3. Claude opens your consent screen. Sign in and click **Allow**.
4. Ask: "save a note called groceries with milk and eggs", then "what are my
   notes?"

For Claude Code:

```bash
claude mcp add --transport http agenthuman-ux https://<your-domain>/mcp
```

Then run `/mcp` inside Claude Code to sign in.

> [!IMPORTANT]
> `PUBLIC_API_URL` must be the exact public origin. It is the OAuth issuer and
> tokens are bound to `<PUBLIC_API_URL>/mcp`, so a wrong value breaks sign-in.

## Make it yours

Everything here is in `src/project/`. The full walkthrough, with a store as
the example, is in [docs/ADAPTING.md](docs/ADAPTING.md).

| Step | File | What you change |
|---|---|---|
| 1. Brand | `branding.ts`, `assets/favicon.svg` | Name, icon, button colour |
| 2. Scopes | `scopes.ts` | What people allow Claude to do, as they will read it |
| 3. Login | `session.ts` | Read your existing session; then set `DEV_LOGIN=false` and delete `dev-login.ts` |
| 4. Tables | `schema.ts`, `migrations/` | Export your users table as `users`; replace the example notes |
| 5. Tools | `tools/*.ts` | One file per area, registered in `tools/index.ts` |
| 6. Disconnect | your settings screen | List `connections`, call `provider.revokeConnection(id, userId)` |

A tool always follows the same three steps:

```ts
server.registerTool(
  "search_products",
  {
    description: "Search the catalog by keyword. Returns name, price and product_id.",
    inputSchema: { query: z.string().min(1) },
    annotations: { readOnlyHint: true },
  },
  async (args, extra) => {
    const { context, error } = await resolveToolContext(db, extra.authInfo, "catalog:read");
    if (error) return result(error, true);              // 1. who is this, allowed?
    const products = await searchProducts(args.query);  // 2. your code, scoped to context.userId
    await logTool(db, context.connectionId, "search_products", args, "allowed");
    return result({ products });                        // 3. log and return
  }
);
```

### Branding

Edit `src/project/branding.ts`, or override per deployment:

| Setting | Env var | Used for |
|---|---|---|
| `name` | `BRAND_NAME` | Consent screen, MCP server title |
| `faviconPath` | `BRAND_FAVICON_PATH` | `/favicon.ico`, `/favicon.<ext>`, the MCP server's `icons`, page icon |
| `accentColor` | `BRAND_ACCENT_COLOR` | Allow and Continue buttons (hex only) |

The favicon can be `.svg`, `.png` or `.ico`. A `.png` is the safest choice for
the widest client support.

## Deploy

Run it as its own service (for example `mcp.yourdomain.com`) pointing at
the same database as the rest of your project, or copy `src/mcp-kit/` and your
`src/project/` files into an existing Express backend and mount it:

```ts
const mcp = createMcpKit({ db, apiUrl, secret, session, branding, scopes, registerTools, serverInfo });
app.use(mcp.router);
```

Any always-on Node host works (Render, Fly, Railway). A static frontend host
does not, because Claude has to reach the server directly. Run
`pnpm db:migrate` on each deploy. The session cookie becomes `Secure`
automatically when `PUBLIC_API_URL` starts with `https://`.

## Endpoints

```text
POST /mcp                                        the connector URL
GET  /.well-known/oauth-protected-resource/mcp   which server issues tokens for /mcp
GET  /.well-known/oauth-authorization-server     OAuth endpoints and capabilities
POST /register                                   dynamic client registration
GET  /authorize                                  starts sign-in, redirects to /connect
POST /token                                      code or refresh token -> tokens
POST /revoke                                     revoke a token
GET  /connect                                    consent screen
POST /oauth/consent                              Allow / Cancel
GET  /favicon.ico, /favicon.<ext>                branded icon
GET  /health                                     database check
GET  /login, POST /login                         dev login (only when DEV_LOGIN=true)
```

## Useful commands

```text
pnpm dev          run with reload
pnpm start        run without reload
pnpm db:migrate   apply migrations/*.sql in order (skips applied ones)
pnpm typecheck    TypeScript check
pnpm e2e          full sign-in and tool flow against a running server
                  (BASE_URL=https://… pnpm e2e for another host)
```

## Important limits

- The dev login signs anyone in with any email. Never run with
  `DEV_LOGIN=true` in production. With it off, `/connect` needs your real
  login wired into `session.ts`.
- Every tool must filter by `context.userId`. The kit checks who the caller
  is; it cannot check what your queries return.
- Approval is a scope check, not an amount limit. For anything that moves
  money or cannot be undone, add its own scope or an approval step (StellaBox
  returns `approval_required` and the owner approves in the app).
- `/mcp` accepts only `POST`; `GET` and `DELETE` return 405 because the server
  keeps no sessions.

Known issues from the last review, not yet fixed:

- The consent screen shows the client's self-chosen name but not where the
  approval is sent. Show the redirect domain before using this with real users.
- A client that omits the optional OAuth `resource` value gets tokens `/mcp`
  rejects. Claude sends it; some other clients may not.
- `/connect` and `/login` send no anti-framing headers.
- Reusing a refresh token revokes all tokens for that connection, with no
  grace period for network retries.
- `whoami` and `get_activity` require `notes:read`; update them when you
  rename scopes.
- Expired codes, tokens and rate-limit rows are not cleaned up.

## Project layout

```text
src/
├── server.ts, app.ts, config.ts
├── mcp-kit/                 reusable engine; copy as-is
│   ├── index.ts             createMcpKit() and tool helpers
│   ├── types.ts             McpKitOptions, Branding, Session
│   ├── schema.ts            connections, oauth_*, tool_activity, rate_limits
│   ├── html.ts, favicon.ts  branded page shell, icon routes
│   ├── oauth/               provider, router, consent page
│   └── mcp/                 /mcp router, resolveToolContext, logTool, result
├── project/                 yours; edit these
│   ├── branding.ts, assets/
│   ├── scopes.ts, schema.ts, session.ts, dev-login.ts
│   └── tools/               index.ts, account.ts, notes.ts
└── db/                      client, merged schema, migration runner
migrations/                  0001 users, 0002 kit tables, 0003 example notes
scripts/e2e.mjs              end-to-end flow
docs/ADAPTING.md             step-by-step guide
```

## Credits

Extracted and generalised from StellaBox's `apps/api` MCP server. StellaBox
binds each token to a wallet grant with on-chain spend caps; here that is a
plain connection (user, client, scopes) you can extend with your own limits.
