import { createHmac, timingSafeEqual } from "node:crypto";
import cors from "cors";
import express, { Router, type RequestHandler } from "express";
import { createOAuthMetadata, mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { sendPage } from "../html.js";
import type { McpKitOptions } from "../types.js";
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

  // CSRF token for the consent form, bound to this request and this user.
  const consentToken = (requestId: string, userId: string) =>
    createHmac("sha256", options.secret)
      .update(`consent:${requestId}:${userId}`)
      .digest("base64url");

  // The SDK's /authorize handler redirects some errors (bad scope, bad PKCE
  // params) straight to the client. Add `iss` to those too: a client that
  // was told we support RFC 9207 rejects any redirect without it.
  const addIssToClientRedirects: RequestHandler = (_request, response, next) => {
    const redirect = response.redirect.bind(response) as (status: number, url: string) => void;
    response.redirect = ((statusOrUrl: number | string, maybeUrl?: string) => {
      const status = typeof statusOrUrl === "number" ? statusOrUrl : 302;
      const target = new URL(String(typeof statusOrUrl === "number" ? maybeUrl : statusOrUrl), issuerUrl);
      if (target.origin !== issuerUrl.origin && !target.searchParams.has("iss")) {
        target.searchParams.set("iss", oauthMetadata.issuer);
      }
      redirect(status, target.toString());
    }) as typeof response.redirect;
    next();
  };

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
  router.use("/authorize", addIssToClientRedirects);
  router.use(
    mcpAuthRouter({
      provider,
      issuerUrl,
      baseUrl: issuerUrl,
      resourceServerUrl,
      scopesSupported,
      resourceName: options.branding.name,
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
        const expected = Buffer.from(consentToken(requestId, userId));
        const given = Buffer.from(String(request.body?.csrf ?? ""));
        if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
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

  return { router, provider };
}
