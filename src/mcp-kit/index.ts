import cors from "cors";
import express, { Router } from "express";
import { createOAuthRouter } from "./oauth/router.js";
import { createMcpRouter } from "./mcp/router.js";
import { createFaviconRouter } from "./favicon.js";
import type { McpKitOptions } from "./types.js";

/**
 * Everything Claude needs, as one Express router:
 *
 *   POST /mcp                                        the connector URL
 *   GET  /.well-known/oauth-protected-resource/mcp   who issues tokens for /mcp
 *   GET  /.well-known/oauth-authorization-server     OAuth endpoints + capabilities
 *   POST /register                                   dynamic client registration
 *   GET  /authorize                                  → redirects to /connect
 *   POST /token                                      code / refresh → tokens
 *   POST /revoke                                     token revocation
 *   GET  /connect                                    consent page
 *   POST /oauth/consent                              Allow / Deny
 *   GET  /favicon.ico, /favicon.<ext>                branded icon
 *
 * Usage:  const kit = createMcpKit({...});  app.use(kit.router);
 * `kit.provider.revokeConnection(id, userId)` powers a "Disconnect" button.
 */
export function createMcpKit(options: McpKitOptions) {
  const router = Router();

  // /mcp is called by Claude's servers and by browser tools like MCP Inspector.
  // It is authenticated by bearer token, never cookies, so any origin is fine.
  router.use(
    "/mcp",
    cors({
      origin: true,
      exposedHeaders: ["WWW-Authenticate", "Mcp-Session-Id"],
      allowedHeaders: ["Authorization", "Content-Type", "Mcp-Protocol-Version", "Mcp-Session-Id"],
    }),
    express.json({ limit: "1mb" })
  );

  router.use(createFaviconRouter(options.branding));

  const oauth = createOAuthRouter(options);
  router.use(oauth.router);
  router.use(createMcpRouter(options, oauth.provider));
  return { router, provider: oauth.provider };
}

export type { Branding, McpKitOptions, Session } from "./types.js";
export { logTool, resolveToolContext, result, type ToolContext } from "./mcp/context.js";
export { escapeHtml, page } from "./html.js";
