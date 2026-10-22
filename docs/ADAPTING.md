# Adapting agenthuman-ux to your project

This works for anything an AI chat app should act on for a signed-in person: a
product, an internal tool, a side project, an existing API you want to expose.
Everything you change is in `src/project/`; `src/mcp-kit/` stays as-is.

Worked example below: a store, where the AI can search products, build a cart,
and check orders for the signed-in customer ("shop from ChatGPT or Claude").

## 1. Brand it → name, favicon, colour

`src/project/branding.ts`

```ts
export const BRANDING: Branding = {
  name: process.env.BRAND_NAME ?? "My Shop",
  faviconPath: process.env.BRAND_FAVICON_PATH ?? fileURLToPath(new URL("./assets/favicon.svg", import.meta.url)),
  accentColor: process.env.BRAND_ACCENT_COLOR ?? "#e4572e",
};
```

- Swap `src/project/assets/favicon.svg` for your icon (`.svg`, `.png` or `.ico`).
  It's served at `/favicon.ico` (the standard location browsers and connector
  UIs look up) and at `/favicon.<ext>`, which the MCP server advertises in its
  `icons` field.
- The name appears on the consent page and as the server title in MCP clients.
- The accent colour is used for the Allow and Continue buttons. Hex only.
- The `BRAND_*` env vars let one codebase run under several brands without
  code changes (see `.env.example`).

## 2. Decide what the AI may do → scopes

`src/project/scopes.ts`

```ts
export const SCOPES = {
  "catalog:read": "Browse products and prices",
  "cart:write": "Add and remove items in your cart",
  "orders:read": "See your orders and their status",
} as const;
```

The consent page lists these strings, so write them for the user. Keep anything
that moves money or can't be undone behind its own scope. For anything risky,
the StellaBox pattern is good: the tool returns `approval_required` with an id,
the user approves in your app, and the AI polls `get_approval`.

## 3. Plug in your login

The consent page (`GET /connect`) and `POST /oauth/consent` need to know which
user is signed in. Everything goes through the `Session` interface
(`src/mcp-kit/types.ts`), implemented in `src/project/session.ts`:

```ts
currentUserId(request) // → your user id or undefined
start(response, userId)
requireUser            // middleware: sets res.locals.userId, else redirect to login
```

Options, easiest first:

- **Same domain as your app** (e.g. API at `api.shop.com`, app at `shop.com`):
  read your app's existing session cookie in `currentUserId` and redirect to
  your real login page in `requireUser`, passing `next` back to `/connect`.
- **Consent page in your frontend** (what StellaBox does with Next.js): change
  the consent URL in `createOAuthRouter` to your web app's `/connect`, render
  the page there (`src/mcp-kit/oauth/consent-page.ts` shows the fields), and have it call `POST /oauth/consent` with the user's
  session. Keep the CSRF check, or use a JSON endpoint protected by your
  session plus `SameSite` cookies and a strict CORS origin.

Then set `DEV_LOGIN=false` and delete `src/project/dev-login.ts` and its line in `app.ts`.

## 4. Use your own tables

In `src/project/schema.ts`, export your existing users table as `users`
(the kit's foreign keys point at it) and replace `notes` with your tables.
Skip `migrations/0001_project_users.sql` and replace `0003_project_notes.sql`.
If your user ids aren't UUIDs, change the `user_id` column types in
`src/mcp-kit/schema.ts` and `migrations/0002_mcp_kit.sql`.

## 5. Write the tools

One file per area under `src/project/tools/` (e.g. `catalog.ts`, `cart.ts`,
`orders.ts`), each exporting a `registerXTools(server, db)` that you add to
`tools/index.ts`. Each tool follows the same three steps:

```ts
// src/project/tools/catalog.ts
import { logTool, resolveToolContext, result } from "../../mcp-kit/index.js";

server.registerTool(
  "search_products",
  {
    title: "Search products",
    description: "Search the catalog by keyword. Returns name, price and product_id.",
    inputSchema: { query: z.string().min(1), limit: z.number().int().max(20).default(10) },
    annotations: { readOnlyHint: true },
  },
  async (args, extra) => {
    const { context, error } = await resolveToolContext(db, extra.authInfo, "catalog:read");
    if (error) return result(error, true);
    const products = await searchProducts(args.query, args.limit); // your code
    await logTool(db, context.connectionId, "search_products", args, "allowed");
    return result({ products });
  }
);
```

Rules that keep it safe:

- **Always scope queries by `context.userId`.** An id from the model must never
  reach another user's data (see `delete_note` in `tools/notes.ts`).
- **Return error codes, don't throw.** `result({ code: "out_of_stock" }, true)`
  lets the AI explain the problem and try something else.
- **Write descriptions for the model.** Say when to use the tool and what each
  argument means. That text is how the AI chooses.
- **Mark hints.** `readOnlyHint` for reads, `destructiveHint` for deletes and
  payments, so clients can ask the user before running them.
- **Keep tools few and task-shaped** ("add_to_cart"), not one per REST endpoint.

## 6. Let users disconnect

Add a settings screen that lists the user's rows in `connections` (join
`oauth_clients` for the name) and calls:

```ts
const mcp = createMcpKit({...});              // in app.ts
await mcp.provider.revokeConnection(connectionId, userId);
```

That revokes every token for that connection; the AI app's next call gets 401.

## 7. Deploy

- Any Node host (Render, Fly, Railway). Set `PUBLIC_API_URL` to the exact public
  origin. It is the OAuth issuer, and tokens are bound to `${PUBLIC_API_URL}/mcp`,
  so a wrong value breaks sign-in.
- Every web AI chat app requires HTTPS. The session cookie turns `Secure` on
  automatically when `PUBLIC_API_URL` starts with `https://`.
- `trust proxy` is already on for hosts that terminate TLS at a proxy.
- Run `pnpm db:migrate` on deploy.

## 8. Before launch

- [ ] Branding set: name, favicon, accent colour
- [ ] `DEV_LOGIN` off; real login wired
- [ ] Every tool filters by `context.userId`
- [ ] Risky tools have their own scope or an approval step
- [ ] Users can see and revoke connections
- [ ] `pnpm e2e` passes against staging (`BASE_URL=https://staging… pnpm e2e`,
      after adapting the login step in the script)
- [ ] Tested in each AI app you support (see the README's "Connect it" table)
