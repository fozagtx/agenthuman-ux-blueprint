import { createHmac, timingSafeEqual } from "node:crypto";
import express, { Router } from "express";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { McpKitOptions } from "../types.js";
import { renderConsentPage, renderExpiredPage } from "./consent-page.js";
import { PostgresOAuthProvider } from "./provider.js";

/** OAuth endpoints (from the SDK), the consent page, and the Allow/Deny handler. */
export function createOAuthRouter(options: McpKitOptions) {
  const issuerUrl = new URL(options.apiUrl);
  const resourceServerUrl = new URL("/mcp", options.apiUrl);
  const scopesSupported = Object.keys(options.scopes);
  const provider = new PostgresOAuthProvider(
    options.db,
    new URL("/connect", options.apiUrl),
    scopesSupported
  );

  // CSRF token for the consent form, bound to this request and this user.
  const consentToken = (requestId: string, userId: string) =>
    createHmac("sha256", options.secret)
      .update(`consent:${requestId}:${userId}`)
      .digest("base64url");

  const router = Router();
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
        response.status(400).send(renderExpiredPage(options.branding));
        return;
      }
      response.send(
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
