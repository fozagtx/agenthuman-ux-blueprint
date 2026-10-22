import type { Request, RequestHandler, Response } from "express";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Database } from "../db/client.js";

/**
 * The kit's only dependency on your login. The consent page needs to know
 * which of your users is looking at it; provide these three functions from
 * whatever auth you use.
 */
export interface Session {
  /** The signed-in user's id, or undefined. */
  currentUserId(request: Request): string | undefined;
  /** Signs the user in on this response. */
  start(response: Response, userId: string): void;
  /** Middleware: sets response.locals.userId, or sends the user to log in. */
  requireUser: RequestHandler;
}

/** How the connector looks: consent/login pages, favicon, MCP server icon. */
export interface Branding {
  /** Shown on the consent page and as the MCP server's title. */
  name: string;
  /** Local .svg, .png or .ico file, served at /favicon.ico and /favicon.<ext>. */
  faviconPath: string;
  /** Hex colour for primary buttons. */
  accentColor?: string;
}

export interface McpKitOptions {
  db: Database;
  /** Public origin, e.g. https://mcp.yourproduct.com. Issuer + resource base. */
  apiUrl: string;
  /** Signs the consent form's CSRF token. */
  secret: string;
  session: Session;
  branding: Branding;
  /** scope → label the user reads on the consent page. */
  scopes: Readonly<Record<string, string>>;
  /** Registers your tools on each per-request MCP server. */
  registerTools: (server: McpServer, db: Database) => void;
  /** MCP server id/version reported to clients, e.g. { name: "my-app", version: "1.0.0" }. */
  serverInfo: { name: string; version: string };
}
