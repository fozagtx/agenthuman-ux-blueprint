import { createHmac, timingSafeEqual } from "node:crypto";
import type { Request } from "express";
import type { Session } from "../mcp-kit/index.js";

/**
 * YOUR LOGIN GOES HERE.
 *
 * The kit only needs the `Session` interface. This default is a stateless
 * HMAC-signed cookie (`userId.expiresAt.signature`) so the blueprint runs on
 * its own. In a real project, read your existing session instead (NextAuth,
 * Clerk, Supabase, passkeys…) and redirect to your real login page.
 */
const COOKIE = "mcp_session";
const MAX_AGE_SECONDS = 7 * 24 * 60 * 60;

function sign(secret: string, value: string) {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

function readCookie(request: Request, name: string) {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

/**
 * Only allow redirects back into this site, never to another origin.
 * Browsers read `/\evil.com` (and tab/newline tricks) as `//evil.com`, so
 * resolve the path against a dummy origin and require it to stay there.
 */
export function safeNext(value: unknown) {
  const next = typeof value === "string" ? value : "";
  if (!next.startsWith("/") || /[\\\u0000-\u001f\u007f]/.test(next)) return "/";
  const base = "https://same-origin.invalid";
  const resolved = new URL(next, base);
  return resolved.origin === base ? `${resolved.pathname}${resolved.search}` : "/";
}

export function createCookieSession(secret: string, secure: boolean): Session {
  function currentUserId(request: Request) {
    const raw = readCookie(request, COOKIE);
    if (!raw) return undefined;
    const [userId, expiresAt, signature] = raw.split(".");
    if (!userId || !expiresAt || !signature) return undefined;
    const expected = Buffer.from(sign(secret, `${userId}.${expiresAt}`));
    const given = Buffer.from(signature);
    if (expected.length !== given.length || !timingSafeEqual(expected, given)) return undefined;
    if (Number(expiresAt) <= Date.now() / 1000) return undefined;
    return userId;
  }

  return {
    currentUserId,
    start(response, userId) {
      const expiresAt = Math.floor(Date.now() / 1000) + MAX_AGE_SECONDS;
      const value = `${userId}.${expiresAt}.${sign(secret, `${userId}.${expiresAt}`)}`;
      response.cookie(COOKIE, value, {
        httpOnly: true,
        secure,
        // Lax: the cookie still rides along when the AI app redirects the user to
        // /connect, but not on cross-site POSTs, so nobody can forge consent.
        sameSite: "lax",
        maxAge: MAX_AGE_SECONDS * 1000,
        path: "/",
      });
    },
    requireUser(request, response, next) {
      const userId = currentUserId(request);
      if (userId) {
        response.locals.userId = userId;
        next();
        return;
      }
      if (request.method === "GET") {
        response.redirect(`/login?next=${encodeURIComponent(request.originalUrl)}`);
        return;
      }
      response.status(401).json({ error: "not_signed_in" });
    },
  };
}
