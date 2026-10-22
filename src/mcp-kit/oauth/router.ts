import { createHmac, timingSafeEqual } from "node:crypto";
import cors from "cors";
import express, { Router, type Request, type RequestHandler } from "express";
import { ipKeyGenerator } from "express-rate-limit";
import { createOAuthMetadata, mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { page, sendPage } from "../html.js";
import type { McpKitOptions } from "../types.js";
import { isClientMetadataUrl } from "./client-metadata.js";
import { renderConnectionsPage } from "./connections-page.js";
import { renderConsentPage, renderExpiredPage } from "./consent-page.js";
import { PostgresOAuthProvider } from "./provider.js";

/**
 * OAuth endpoints (from the SDK), the metadata AI clients discover them by,
 * the consent page, and the Allow/Deny handler.
 *
 * Compatibility notes, so the same server works in every MCP chat client:
 *   - CIMD and DCR are both offered. ChatGPT, Claude and Codex prefer CIMD;
 *     Le Chat uses DCR. Claude only picks CIMD when "none" is also listed in
 *     token_endpoint_auth_methods_supported, which the SDK already includes.
 *   - Every redirect back to a client carries `iss` (RFC 9207). ChatGPT then
 *     uses its stable callback https://chatgpt.com/connector_platform_oauth_redirect.
 *   - Protected resource metadata is served at both the RFC 9728 path
 *     (/.well-known/oauth-protected-resource/mcp) and the root path some
 *     clients probe (/.well-known/oauth-protected-resource).
 */
export function createOAuthRouter(options: McpKitOptions) {
  const issuerUrl = new URL(options.apiUrl);
  const resourceServerUrl = new URL("/mcp", options.apiUrl);
  const scopesSupported = Object.keys(options.scopes);

  const provider = new PostgresOAuthProvider(options.db, {
    issuer: issuerUrl.href,
    resource: resourceServerUrl,
    consentUrl: new URL("/connect", options.apiUrl),
    supportedScopes: scopesSupported,
    clientMetadata: { allowLoopback: options.allowLoopbackClientMetadata ?? false },
  });

  const oauthMetadata = {
    ...createOAuthMetadata({ provider, issuerUrl, baseUrl: issuerUrl, scopesSupported }),
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  };
  const protectedResourceMetadata = {
    resource: resourceServerUrl.href,
    authorization_servers: [oauthMetadata.issuer],
    scopes_supported: scopesSupported,
    resource_name: options.branding.name,
  };

  // CSRF tokens for the consent and disconnect forms, bound to the user.
  const formToken = (purpose: string, userId: string) =>
    createHmac("sha256", options.secret).update(`${purpose}:${userId}`).digest("base64url");
  const consentToken = (requestId: string, userId: string) => formToken(`consent:${requestId}`, userId);
  const tokenMatches = (expected: string, given: unknown) => {
    const a = Buffer.from(expected);
    const b = Buffer.from(String(given ?? ""));
    return a.length === b.length && timingSafeEqual(a, b);
  };
  const allowLoopback = options.allowLoopbackClientMetadata ?? false;

  // The SDK limits per IP by default, but ChatGPT, Claude and Le Chat call
  // /token and /register from shared backend IPs, so one busy app would lock
  // out all its users. Key on client_id + IP instead.
  const perClient = (windowMs: number, limit: number) => ({
    windowMs,
    limit,
    max: limit, // the SDK sets `max`; set both so ours wins either way
    keyGenerator: (request: Request) =>
      `${String(request.body?.client_id ?? request.query.client_id ?? "")}|${ipKeyGenerator(request.ip ?? "")}`,
  });

  // The SDK's /authorize handler redirects some errors (bad scope, bad PKCE
  // params) straight to the client, before any user interaction.
  //   - Add `iss`: a client told we support RFC 9207 rejects redirects without it.
  //   - For clients that aren't verified (DCR: anyone can register any
  //     redirect URI), show the error here instead, so our domain can't be
  //     used as an open redirector in phishing links (RFC 9700 §4.11.2).
  const guardClientRedirects: RequestHandler = (request, response, next) => {
    const verified = isClientMetadataUrl(String(request.query.client_id ?? ""), { allowLoopback });
    const redirect = response.redirect.bind(response) as (status: number, url: string) => void;
    response.redirect = ((statusOrUrl: number | string, maybeUrl?: string) => {
      const status = typeof statusOrUrl === "number" ? statusOrUrl : 302;
      const target = new URL(String(typeof statusOrUrl === "number" ? maybeUrl : statusOrUrl), issuerUrl);
      if (target.origin === issuerUrl.origin) return redirect(status, target.toString());
      const error = target.searchParams.get("error");
      if (error && !verified) {
        sendPage(
          response,
          page(options.branding, "Can't connect", `<h1>Can't connect this app</h1><p>The app sent an invalid sign-in request (${escapeError(error)}). Start the connection again from your AI app.</p>`),
          400
        );
        return;
      }
      if (!target.searchParams.has("iss")) target.searchParams.set("iss", oauthMetadata.issuer);
      redirect(status, target.toString());
    }) as typeof response.redirect;
    next();
  };
  const escapeError = (code: string) => code.replace(/[^a-z_]/g, "");

  const router = Router();
  const metadataCors = cors({ origin: true, methods: ["GET", "OPTIONS"] });
  router.use("/.well-known/oauth-authorization-server", metadataCors);
  router.get("/.well-known/oauth-authorization-server", (_request, response) => {
    response.json(oauthMetadata);
  });
  router.use("/.well-known/oauth-protected-resource", metadataCors);
  router.get("/.well-known/oauth-protected-resource", (_request, response) => {
    response.json(protectedResourceMetadata);
  });
  router.use("/authorize", guardClientRedirects);
  router.use(
    mcpAuthRouter({
      provider,
      issuerUrl,
      baseUrl: issuerUrl,
      resourceServerUrl,
      scopesSupported,
      resourceName: options.branding.name,
      tokenOptions: { rateLimit: perClient(15 * 60 * 1000, 300) },
      revocationOptions: { rateLimit: perClient(15 * 60 * 1000, 300) },
      // Registration has no client_id yet; ChatGPT registers once per
      // connection from shared IPs, so allow more than the SDK's 20/hour.
      clientRegistrationOptions: { rateLimit: { windowMs: 60 * 60 * 1000, limit: 300, max: 300 } },
    })
  );

  router.get("/connect", options.session.requireUser, async (request, response, next) => {
    try {
      const pending = await provider.pendingAuthorization(String(request.query.requestId ?? ""));
      if (!pending) {
        sendPage(response, renderExpiredPage(options.branding), 400);
        return;
      }
      sendPage(
        response,
        renderConsentPage({
          pending,
          branding: options.branding,
          scopeLabels: options.scopes,
          csrf: consentToken(pending.requestId, response.locals.userId as string),
        })
      );
    } catch (error) {
      next(error);
    }
  });

  router.post(
    "/oauth/consent",
    express.urlencoded({ extended: false }),
    options.session.requireUser,
    async (request, response, next) => {
      try {
        const userId = response.locals.userId as string;
        const requestId = String(request.body?.requestId ?? "");
        if (!tokenMatches(consentToken(requestId, userId), request.body?.csrf)) {
          response.status(403).json({ error: "invalid_consent" });
          return;
        }
        const redirectUrl =
          request.body?.decision === "allow"
            ? await provider.consent(requestId, userId)
            : await provider.deny(requestId);
        response.redirect(303, redirectUrl);
      } catch (error) {
        next(error);
      }
    }
  );

  router.get("/connections", options.session.requireUser, async (_request, response, next) => {
    try {
      const userId = response.locals.userId as string;
      sendPage(
        response,
        renderConnectionsPage({
          branding: options.branding,
          connections: await provider.listConnections(userId),
          scopeLabels: options.scopes,
          csrf: formToken("connections", userId),
        })
      );
    } catch (error) {
      next(error);
    }
  });

  router.post(
    "/connections/disconnect",
    express.urlencoded({ extended: false }),
    options.session.requireUser,
    async (request, response, next) => {
      try {
        const userId = response.locals.userId as string;
        if (!tokenMatches(formToken("connections", userId), request.body?.csrf)) {
          response.status(403).json({ error: "invalid_request" });
          return;
        }
        const connectionId = String(request.body?.connectionId ?? "");
        if (/^[0-9a-f-]{36}$/i.test(connectionId)) await provider.revokeConnection(connectionId, userId);
        response.redirect(303, "/connections");
      } catch (error) {
        next(error);
      }
    }
  );

  return { router, provider };
}
