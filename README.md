# agenthuman-ux

![A human finger touching a robotic finger](docs/assets/hero.png)

Let people use your project from the AI chat app they already use — ChatGPT,
Claude, Le Chat, Gemini and other MCP clients. They paste one URL, sign in,
click Allow, and the AI can call your tools on their behalf.

Repository: https://github.com/fozagtx/agenthuman-ux-blueprint

## What is it?

agenthuman-ux is a blueprint for a remote MCP server with its own OAuth sign-in.
It is a backend service (Node, Express, Postgres), extracted from StellaBox and
generalised. Use it for any project where an AI should act for a signed-in
person: a product, an internal tool, a side project, or an existing API.

It has two parts:

**The kit** (`src/mcp-kit/`) handles the protocol: the OAuth server every AI
app signs in through, the consent screen, the "Connected apps" page, the
`/mcp` endpoint, the favicon and the audit log. It is required, and you should
not need to edit it.

**Your project** (`src/project/`) is everything that changes per project:
branding, scopes, login, tables and tools. You edit all of it.

`src/app.ts` is the only file that connects the two. The kit never imports your
project's code; it receives branding, scopes, tools and login through
`createMcpKit()`. The one exception is its tables, which point at your `users`
table.

## How it works

```text
              AI chat app (ChatGPT, Claude, Le Chat, Gemini…)
                                  |
                                  v
                    POST /mcp (no token yet)
                                  |
                                  v
                401 + "sign in at this server"
                                  |
              +-------------------+-------------------+
              |                                       |
   client_id is a URL (CIMD)             POST /register (DCR)
   we fetch and verify it                 random client_id
   ChatGPT, Claude, Codex                 Le Chat, fallback
              |                                       |
              +-------------------+-------------------+
                                  |
                                  v
                    GET /authorize -> GET /connect
                       (your consent screen)
                                  |
                 signed in? -- no --> your login --+
                                  |                |
                                 yes <-------------+
                                  |
                       Allow  /       \  Cancel
                             v         v
              code + iss to the app    error=access_denied + iss
                             |
                             v
           POST /token -> access token (15 min)
                          refresh token (rotates; grant ends after 90 days)
                             |
                             v
           POST /mcp (Bearer token) -> your tools run as that user
```

Each Allow creates a **connection**: one user, one AI app, the scopes they
approved. Every token belongs to a connection, so disconnecting it cuts the app
off on its next call. Every tool call checks the token, the connection, the
scope and a rate limit of 120 calls per minute, then is written to the audit
log.

## Why use it?

- Works with the major web AI chat apps from one URL. It supports both ways
  they identify themselves: Client ID Metadata Documents (preferred by
  ChatGPT, Claude and Codex) and dynamic client registration (used by Le Chat).
- People see what the AI may do before they allow it, and can disconnect any
  app from a "Connected apps" page.
- Follows the MCP authorization spec: protected resource metadata, PKCE (S256),
  `resource` binding, refresh-token rotation, revocation, and `iss` on every
  redirect (RFC 9207), which lets ChatGPT use its stable callback URL.
- Codes and tokens are stored only as SHA-256 hashes.
- `/mcp` is stateless, so you can run several instances with no sticky sessions.
- Name, favicon and button colour are set in one file, or per deployment with
  env vars.
- An end-to-end script runs the full sign-in, tool and security flow (59 checks).

It has not yet been tested against the live chat apps; that needs a public
HTTPS URL (see [Connect it](#connect-it)). The e2e script reproduces each
client's registration method, including a CIMD document shaped like ChatGPT's.

## Install

Requires Node 22 or newer, pnpm, and Postgres 16 (Docker or a local install).

```bash
git clone https://github.com/fozagtx/agenthuman-ux-blueprint.git my-project-mcp
cd my-project-mcp
pnpm install
cp .env.example .env
```

Then set `SESSION_SECRET` in `.env` (at least 32 characters):

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

Try it in a browser without an AI app:

```bash
npx @modelcontextprotocol/inspector
```

Choose transport "Streamable HTTP" and URL `http://localhost:4000/mcp`. The
inspector runs the sign-in; with `DEV_LOGIN=true` any email signs you in.

## Connect it

Every web AI app calls your server from the internet, so it needs a public
HTTPS URL. Locally:

```bash
cloudflared tunnel --url http://localhost:4000
```

Set `PUBLIC_API_URL` in `.env` to the tunnel URL and restart. In production,
set it to your deployed domain. Then add `https://<your-domain>/mcp` in the app:

| App | Where | Notes |
|---|---|---|
| **ChatGPT** | Turn on Developer mode in settings, then create an app/connector with the URL | Uses CIMD with its stable callback, because this server returns `iss`. `whoami` is marked as the profile tool so people can connect several accounts. |
| **Claude** (claude.ai, desktop, mobile) | Settings → Connectors → Add custom connector | Uses CIMD, since the server advertises it and `none` token auth; DCR otherwise. |
| **Le Chat** (Mistral) | Connectors → + Add Connector → Custom MCP Connector | Admin only (the account owner on Free, Pro and Student plans). The connector name can't contain spaces. Uses DCR. Reconnect after you change tools. |
| **Gemini** (web app) | Settings → Connected apps → add a custom app | Eligibility rules apply; at the time of writing, secondary sources report personal accounts, 18+, US, English. Check Google's help pages. |
| **Claude Code** | `claude mcp add --transport http my-app https://<your-domain>/mcp`, then `/mcp` | Uses its own CIMD document. |
| **MCP Inspector** | `npx @modelcontextprotocol/inspector` | For debugging the flow. |

After Allow, people can review and disconnect apps at
`https://<your-domain>/connections`.

> [!IMPORTANT]
> `PUBLIC_API_URL` must be the exact public origin. It is the OAuth issuer
> and tokens are bound to `<PUBLIC_API_URL>/mcp`, so a wrong value breaks
> sign-in in every app.

## Make it yours

Everything here is in `src/project/`. The full walkthrough, with a store as the
example, is in [docs/ADAPTING.md](docs/ADAPTING.md).

| Step | File | What you change |
|---|---|---|
| 1. Brand | `branding.ts`, `assets/favicon.svg` | Name, icon, button colour |
| 2. Scopes | `scopes.ts` | What people allow the AI to do, as they will read it |
| 3. Login | `session.ts` | Read your existing session; then set `DEV_LOGIN=false` and delete `dev-login.ts` |
| 4. Tables | `schema.ts`, `migrations/` | Export your users table as `users`; replace the example notes |
| 5. Tools | `tools/*.ts` | One file per area, registered in `tools/index.ts` |
| 6. Link it | your app's settings | Link to `/connections` so people can disconnect apps |

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
    const { context, error } = await toolContext(db, extra.authInfo, "catalog:read");
    if (error) return result(error, true);              // 1. who is this, allowed?
    const products = await searchProducts(args.query);  // 2. your code, scoped to context.userId
    await logTool(db, context.connectionId, "search_products", args, "allowed");
    return result({ products });                        // 3. log and return
  }
);
```

`toolContext` is typed to your scopes, so a misspelled or renamed scope fails
the typecheck.

### Branding

Edit `src/project/branding.ts`, or override per deployment:

| Setting | Env var | Used for |
|---|---|---|
| `name` | `BRAND_NAME` | Consent and Connected apps pages, MCP server title |
| `faviconPath` | `BRAND_FAVICON_PATH` | `/favicon.ico`, `/favicon.<ext>`, the MCP server's `icons`, page icon |
| `accentColor` | `BRAND_ACCENT_COLOR` | Allow and Continue buttons (hex only) |

The favicon can be `.svg`, `.png` or `.ico`. A `.png` is the safest choice for
the widest client support.

## Deploy

Run it as its own service (for example `mcp.yourdomain.com`) pointing at the
same database as the rest of your project, or copy `src/mcp-kit/` and your
`src/project/` files into an existing Express backend and mount it:

```ts
const mcp = createMcpKit({ db, apiUrl, secret, session, branding, scopes, registerTools, serverInfo });
app.use(mcp.router);
```

Any always-on Node host works (Render, Fly, Railway). A static frontend host
does not, because the AI apps have to reach the server directly.

- Run `pnpm db:migrate` on each deploy.
- Set `NODE_ENV=production`. The server then refuses to start if `DEV_LOGIN`
  is still on.
- Set `TRUST_PROXY` to the number of proxies in front of the server (1 on
  Render, Fly or Railway; 0 if exposed directly), or rate limits can be
  bypassed with a forged `X-Forwarded-For`.
- The session cookie becomes `Secure` automatically when `PUBLIC_API_URL`
  starts with `https://`.

## Endpoints

```text
POST /mcp                                        the connector URL
GET  /.well-known/oauth-protected-resource/mcp   which server issues tokens for /mcp
GET  /.well-known/oauth-protected-resource       same, at the root path
GET  /.well-known/oauth-authorization-server     OAuth endpoints and capabilities
POST /register                                   dynamic client registration
GET  /authorize                                  starts sign-in, redirects to /connect
POST /token                                      code or refresh token -> tokens
POST /revoke                                     revoke a token (refresh token ends the grant)
GET  /connect                                    consent screen
POST /oauth/consent                              Allow / Cancel
GET  /connections                                Connected apps page
POST /connections/disconnect                     disconnect one app
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
pnpm e2e          full sign-in, tool and security flow against a running local server
```

## Security

The server is built on the assumption that anyone can register a client,
start a sign-in, or send a user a link. What it does about that:

- **Tokens.** 256-bit access and 384-bit refresh tokens, stored as SHA-256
  hashes and bound to one client, one connection and this server's `/mcp`.
  Refresh tokens rotate. Presenting an old one revokes the whole grant, and
  revoked hashes are kept until they would have expired, so a stolen copy is
  still caught later. Every grant ends 90 days after the user allowed it.
- **Codes.** Single use, five minutes, bound to client, redirect URI and PKCE.
  Replaying a code revokes the tokens it issued.
- **Consent.** CSRF-protected, cannot be framed, and shows where the approval
  will be sent. Apps that identified by CIMD are labelled with their verified
  domain. Self-registered names are marked unverified, stripped of invisible
  characters and capped in length.
- **CIMD fetching.** HTTPS on port 443 to public addresses only, checked at
  connect time and for every IPv6 spelling of a private address. No
  redirects, 5-second total deadline, 64 KB cap, 16 fetches in flight,
  failures cached. Errors are generic, so the endpoint can't be used to scan
  your network.
- **Redirects.** Unverified (DCR) clients never get an automatic error
  redirect, so your domain can't be used as an open redirector.
- **Rate limits.** `/token`, `/revoke` and `/register` are limited per client
  and IP, so one busy AI app doesn't lock out its other users. Tool calls are
  limited per connection.
- **Cleanup.** Expired codes, tokens, sign-in requests, unused clients, ended
  connections and audit rows older than 90 days are deleted hourly.

Known limits:

- The dev login signs anyone in with any email. It exists only so the
  blueprint runs on its own; replace it before real users.
- Every tool must filter by `context.userId`. The kit checks who the caller
  is; it cannot check what your queries return.
- A scope is all-or-nothing. For anything that moves money or cannot be
  undone, add its own scope or an approval step (StellaBox returns
  `approval_required` and the owner approves in the app).
- DCR client secrets are stored as issued, because the SDK compares them
  directly. CIMD clients have no secret.
- The SDK's own rate limits are in memory, so with several instances each one
  counts separately.

## Project layout

```text
src/
├── server.ts, app.ts, config.ts
├── mcp-kit/                 reusable engine; copy as-is
│   ├── index.ts             createMcpKit() and tool helpers
│   ├── types.ts             McpKitOptions, Branding, Session
│   ├── schema.ts            connections, oauth_*, tool_activity, rate_limits
│   ├── html.ts, favicon.ts  branded page shell, icon routes
│   ├── oauth/               provider, router, client-metadata (CIMD), consent and connections pages
│   └── mcp/                 /mcp router, resolveToolContext, logTool, result
├── project/                 yours; edit these
│   ├── branding.ts, assets/
│   ├── scopes.ts, schema.ts, session.ts, dev-login.ts
│   └── tools/               index.ts, context.ts, account.ts, notes.ts
└── db/                      client, merged schema, migration runner
migrations/                  0001 users, 0002 kit tables, 0003 example notes, 0004 CIMD cache
scripts/e2e.mjs              end-to-end flow
docs/ADAPTING.md             step-by-step guide
```

## Credits

Extracted and generalised from StellaBox's `apps/api` MCP server. StellaBox
binds each token to a wallet grant with on-chain spend caps; here that is a
plain connection (user, client, scopes) you can extend with your own limits.
