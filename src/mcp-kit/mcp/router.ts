import { Router } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { McpKitOptions } from "../types.js";
import { faviconMimeType } from "../favicon.js";

/**
 * POST /mcp. Stateless Streamable HTTP: every request builds a fresh server,
 * so it scales horizontally with no sticky sessions. requireBearerAuth answers
 * 401 + WWW-Authenticate when the token is missing, which is what starts
 * Claude's OAuth flow.
 */
export function createMcpRouter(options: McpKitOptions, verifier: OAuthTokenVerifier) {
  const bearer = requireBearerAuth({
    verifier,
    resourceMetadataUrl: new URL("/.well-known/oauth-protected-resource/mcp", options.apiUrl).toString(),
    expectedResource: new URL("/mcp", options.apiUrl),
  });
  const extension = options.branding.faviconPath.split(".").pop()!.toLowerCase();
  const serverInfo = {
    ...options.serverInfo,
    title: options.branding.name,
    icons: [{
      src: new URL(`/favicon.${extension}`, options.apiUrl).toString(),
      mimeType: faviconMimeType(options.branding.faviconPath),
    }],
  };

  const router = Router();
  router.post("/mcp", bearer, async (request, response, next) => {
    try {
      const server = new McpServer(serverInfo);
      options.registerTools(server, options.db);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      response.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(request, response, request.body);
    } catch (error) {
      next(error);
    }
  });
  // Stateless servers have no SSE stream to resume and no session to delete.
  router.all("/mcp", (_request, response) => {
    response.set("Allow", "POST").status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed." },
      id: null,
    });
  });
  return router;
}
