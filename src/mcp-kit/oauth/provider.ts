import { randomBytes, randomUUID, createHash, timingSafeEqual } from "node:crypto";
import type { Response } from "express";
import { and, eq, gt, isNull, lt, or, sql } from "drizzle-orm";
import type {
  AuthorizationParams,
  OAuthServerProvider,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { Database } from "../../db/client.js";
import {
  connections,
  oauthAuthorizationRequests,
  oauthClients,
  oauthCodes,
  oauthTokens,
  rateLimits,
  toolActivity,
} from "../schema.js";
import {
  fetchClientMetadata,
  isClientMetadataUrl,
  type ClientMetadataOptions,
} from "./client-metadata.js";

const ACCESS_TOKEN_SECONDS = 15 * 60;
const REFRESH_TOKEN_SECONDS = 30 * 24 * 60 * 60;
const AUTHORIZATION_REQUEST_SECONDS = 10 * 60;
const CODE_SECONDS = 5 * 60;
const CLIENT_METADATA_CACHE_SECONDS = 60 * 60;
// A connection ends this long after the user approved it, however often it
// refreshes, so a leaked refresh token can't grant access forever.
const CONNECTION_MAX_AGE_SECONDS = 90 * 24 * 60 * 60;
const UNUSED_CLIENT_DAYS = 7;
const TOOL_ACTIVITY_DAYS = 90;

const connectionExpiresAt = (createdAt: Date) =>
  new Date(createdAt.getTime() + CONNECTION_MAX_AGE_SECONDS * 1000);

function digest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function constantTimeEqual(left: string, right: string) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** RFC 8707 resources compare equal ignoring a fragment and one trailing slash. */
function sameResource(a: string, b: string) {
  const normalize = (value: string) => {
    const url = new URL(value);
    url.hash = "";
    return url.href.replace(/\/$/, "");
  };
  return normalize(a) === normalize(b);
}

/**
 * Client names are chosen by the client. Strip control and format characters
 * (bidi overrides, zero-width joiners) so one can't visually impersonate
 * another app, and cap the length.
 */
function displayName(name: string) {
  const clean = name.replace(/[\p{Cc}\p{Cf}]/gu, "").replace(/\s+/g, " ").trim();
  return (clean.length > 64 ? `${clean.slice(0, 63)}…` : clean) || "Unnamed app";
}

/** "chatgpt.com", "localhost:3000", or "myapp://" for custom-scheme apps. */
function redirectTarget(redirectUri: string) {
  const url = new URL(redirectUri);
  if (url.protocol === "https:" || url.protocol === "http:") return url.host;
  return `${url.protocol}//${url.host}`;
}

export type PendingAuthorization = {
  requestId: string;
  clientName: string;
  scopes: string[];
  /** Where the code will be sent. Shown so the user can spot a look-alike app. */
  redirectHost: string;
  /**
   * Set when the client identified itself with a metadata URL (CIMD): its
   * host is proven by HTTPS, unlike a self-chosen DCR client_name.
   */
  verifiedClientHost?: string;
};

export type ProviderOptions = {
  /** Exact `issuer` string from the authorization server metadata. Sent as `iss` (RFC 9207). */
  issuer: string;
  /** The MCP endpoint tokens are minted for, e.g. https://mcp.example.com/mcp. */
  resource: URL;
  /** Where /authorize sends the user to approve. Gets ?requestId=… appended. */
  consentUrl: URL;
  supportedScopes: string[];
  clientMetadata?: ClientMetadataOptions;
};

/**
 * OAuth 2.1 authorization server backed by Postgres, implementing the MCP SDK's
 * provider interface. The SDK handles the HTTP side (/authorize, /token,
 * /register, /revoke); this class stores and checks state.
 *
 * Clients identify themselves one of two ways:
 *   - CIMD: client_id is an HTTPS URL to a metadata document (ChatGPT, Claude,
 *     Claude Code, Codex prefer this)
 *   - DCR:  the client POSTs /register and gets a random client_id (Le Chat,
 *     and the fallback for everyone else)
 *
 * Flow: /authorize stores a pending request and redirects the user to the
 * consent page → the user approves → consent() mints a one-time code → the
 * client exchanges it (with its PKCE verifier) for access + refresh tokens.
 */
export class PostgresOAuthProvider implements OAuthServerProvider {
  // PKCE is checked inside exchangeAuthorizationCode with a constant-time compare.
  readonly skipLocalPkceValidation = true;
  readonly clientsStore: OAuthRegisteredClientsStore;

  constructor(
    private readonly db: Database,
    private readonly options: ProviderOptions
  ) {
    this.clientsStore = {
      getClient: (clientId) =>
        isClientMetadataUrl(clientId, options.clientMetadata)
          ? this.metadataClient(clientId)
          : this.registeredClient(clientId),
      // The SDK has already issued a client_secret when the client asked for
      // client_secret_post. Keep the client's chosen auth method so the
      // registration response never says "none" while also requiring a secret.
      registerClient: async (metadata) => {
        // The SDK reads client secrets from the request body only, so a
        // client_secret_basic client could never authenticate.
        if (metadata.token_endpoint_auth_method === "client_secret_basic") {
          throw new InvalidClientMetadataError("Use token_endpoint_auth_method none or client_secret_post");
        }
        const clientId = randomBytes(24).toString("base64url");
        const client = {
          ...metadata,
          client_id: clientId,
          client_id_issued_at: Math.floor(Date.now() / 1000),
        } as OAuthClientInformationFull;
        await db.insert(oauthClients).values({
          id: clientId,
          name: String(metadata.client_name ?? clientId),
          redirectUris: metadata.redirect_uris,
          metadata: client as unknown as Record<string, unknown>,
        });
        return client;
      },
    };
  }

  private async registeredClient(clientId: string) {
    const [client] = await this.db
      .select()
      .from(oauthClients)
      .where(eq(oauthClients.id, clientId))
      .limit(1);
    return client?.metadata as OAuthClientInformationFull | undefined;
  }

  /**
   * CIMD client: use the cached document if it's fresh, otherwise fetch and
   * validate it again. The row is kept in oauth_clients so connections,
   * codes and tokens can reference it like any registered client.
   */
  private async metadataClient(clientId: string) {
    const [cached] = await this.db
      .select()
      .from(oauthClients)
      .where(eq(oauthClients.id, clientId))
      .limit(1);
    const fresh =
      cached?.metadataFetchedAt &&
      Date.now() - cached.metadataFetchedAt.getTime() < CLIENT_METADATA_CACHE_SECONDS * 1000;
    if (fresh) return cached.metadata as unknown as OAuthClientInformationFull;
    const client = await fetchClientMetadata(clientId, this.options.clientMetadata);
    const row = {
      name: String(client.client_name),
      redirectUris: client.redirect_uris,
      metadata: client as unknown as Record<string, unknown>,
      metadataFetchedAt: new Date(),
    };
    await this.db
      .insert(oauthClients)
      .values({ id: clientId, ...row })
      .onConflictDoUpdate({ target: oauthClients.id, set: row });
    return client;
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    response: Response
  ) {
    // Tokens only ever work at our /mcp, so a request for another resource
    // can't be honoured; a missing one means ours.
    if (params.resource && !sameResource(params.resource.href, this.options.resource.href)) {
      throw new InvalidTargetError("Unknown resource");
    }
    const { supportedScopes } = this.options;
    const scopes = params.scopes?.length
      ? params.scopes.filter((scope) => supportedScopes.includes(scope))
      : supportedScopes;
    if (scopes.length === 0) throw new InvalidScopeError("No supported scopes requested");
    const requestId = randomBytes(24).toString("base64url");
    await this.db.insert(oauthAuthorizationRequests).values({
      requestId,
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      state: params.state ?? null,
      codeChallenge: params.codeChallenge,
      scopes,
      resource: this.options.resource.href,
      expiresAt: new Date(Date.now() + AUTHORIZATION_REQUEST_SECONDS * 1000),
    });
    const consent = new URL(this.options.consentUrl);
    consent.searchParams.set("requestId", requestId);
    response.redirect(consent.toString());
  }

  /** What the consent page needs to show: who is asking, for what, and where it goes. */
  async pendingAuthorization(requestId: string): Promise<PendingAuthorization | undefined> {
    const [pending] = await this.db
      .select({
        requestId: oauthAuthorizationRequests.requestId,
        scopes: oauthAuthorizationRequests.scopes,
        redirectUri: oauthAuthorizationRequests.redirectUri,
        clientId: oauthClients.id,
        clientName: oauthClients.name,
      })
      .from(oauthAuthorizationRequests)
      .innerJoin(oauthClients, eq(oauthClients.id, oauthAuthorizationRequests.clientId))
      .where(
        and(
          eq(oauthAuthorizationRequests.requestId, requestId),
          isNull(oauthAuthorizationRequests.consumedAt),
          gt(oauthAuthorizationRequests.expiresAt, new Date())
        )
      )
      .limit(1);
    if (!pending) return undefined;
    return {
      requestId: pending.requestId,
      clientName: displayName(pending.clientName),
      scopes: pending.scopes,
      redirectHost: redirectTarget(pending.redirectUri),
      ...(isClientMetadataUrl(pending.clientId, this.options.clientMetadata)
        ? { verifiedClientHost: new URL(pending.clientId).host }
        : {}),
    };
  }

  /** Redirect back to the client with `iss` (RFC 9207), as every response must. */
  private clientRedirect(redirectUri: string, params: Record<string, string | null>) {
    const redirect = new URL(redirectUri);
    for (const [key, value] of Object.entries(params)) {
      if (value) redirect.searchParams.set(key, value);
    }
    redirect.searchParams.set("iss", this.options.issuer);
    return redirect.toString();
  }

  /**
   * The user approved. Create the connection, mint a one-time code, and return
   * the client's redirect URL. Call this only for a signed-in user.
   */
  async consent(requestId: string, userId: string): Promise<string> {
    const [pending] = await this.db
      .select()
      .from(oauthAuthorizationRequests)
      .where(
        and(
          eq(oauthAuthorizationRequests.requestId, requestId),
          isNull(oauthAuthorizationRequests.consumedAt),
          gt(oauthAuthorizationRequests.expiresAt, new Date())
        )
      )
      .limit(1);
    if (!pending) throw new Error("invalid_consent");
    const code = randomBytes(32).toString("base64url");
    await this.db.transaction(async (transaction) => {
      const [consumed] = await transaction
        .update(oauthAuthorizationRequests)
        .set({ userId, consumedAt: new Date() })
        .where(
          and(
            eq(oauthAuthorizationRequests.id, pending.id),
            isNull(oauthAuthorizationRequests.consumedAt)
          )
        )
        .returning();
      if (!consumed) throw new Error("invalid_consent");
      const [connection] = await transaction
        .insert(connections)
        .values({ userId, clientId: pending.clientId, scopes: pending.scopes })
        .returning({ id: connections.id });
      await transaction.insert(oauthCodes).values({
        codeHash: digest(code),
        clientId: pending.clientId,
        connectionId: connection!.id,
        redirectUri: pending.redirectUri,
        codeChallenge: pending.codeChallenge,
        scopes: pending.scopes,
        resource: pending.resource,
        expiresAt: new Date(Date.now() + CODE_SECONDS * 1000),
      });
    });
    return this.clientRedirect(pending.redirectUri, { code, state: pending.state });
  }

  /** The user said no. OAuth requires telling the client with error=access_denied. */
  async deny(requestId: string): Promise<string> {
    const [pending] = await this.db
      .update(oauthAuthorizationRequests)
      .set({ consumedAt: new Date() })
      .where(
        and(
          eq(oauthAuthorizationRequests.requestId, requestId),
          isNull(oauthAuthorizationRequests.consumedAt)
        )
      )
      .returning();
    if (!pending) throw new Error("invalid_consent");
    return this.clientRedirect(pending.redirectUri, { error: "access_denied", state: pending.state });
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string) {
    const [stored] = await this.db
      .select()
      .from(oauthCodes)
      .where(
        and(
          eq(oauthCodes.codeHash, digest(code)),
          eq(oauthCodes.clientId, client.client_id),
          isNull(oauthCodes.consumedAt),
          gt(oauthCodes.expiresAt, new Date())
        )
      )
      .limit(1);
    if (!stored) throw new InvalidGrantError("Invalid or expired authorization grant");
    return stored.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    code: string,
    codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    if (resource && !sameResource(resource.href, this.options.resource.href)) {
      throw new InvalidTargetError("Unknown resource");
    }
    const [stored] = await this.db
      .select()
      .from(oauthCodes)
      .where(and(eq(oauthCodes.codeHash, digest(code)), eq(oauthCodes.clientId, client.client_id)))
      .limit(1);
    if (stored?.consumedAt) {
      // A code used twice was intercepted: revoke what the first use issued.
      await this.revokeConnectionTokens(stored.connectionId);
      throw new InvalidGrantError("Invalid or expired authorization grant");
    }
    if (!stored || stored.expiresAt <= new Date() || !codeVerifier || stored.redirectUri !== redirectUri) {
      throw new InvalidGrantError("Invalid or expired authorization grant");
    }
    const verifierHash = createHash("sha256").update(codeVerifier).digest("base64url");
    if (!constantTimeEqual(verifierHash, stored.codeChallenge)) {
      throw new InvalidGrantError("Invalid or expired authorization grant");
    }
    const [consumed] = await this.db
      .update(oauthCodes)
      .set({ consumedAt: new Date() })
      .where(and(eq(oauthCodes.id, stored.id), isNull(oauthCodes.consumedAt)))
      .returning();
    if (!consumed) throw new InvalidGrantError("Invalid or expired authorization grant");
    return this.issueTokenPair(stored.connectionId, client.client_id, stored.scopes);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    if (resource && !sameResource(resource.href, this.options.resource.href)) {
      throw new InvalidTargetError("Unknown resource");
    }
    const [stored] = await this.db
      .select()
      .from(oauthTokens)
      .where(
        and(
          eq(oauthTokens.hash, digest(refreshToken)),
          eq(oauthTokens.type, "refresh"),
          eq(oauthTokens.clientId, client.client_id),
          gt(oauthTokens.expiresAt, new Date())
        )
      )
      .limit(1);
    if (!stored) throw new InvalidGrantError("Invalid or expired authorization grant");
    if (stored.revokedAt) {
      // A rotated refresh token came back, so two parties hold copies and we
      // can't tell which is legitimate. Revoke every token from this consent;
      // the real user reconnects, the thief is locked out.
      await this.revokeFamily(stored.familyId);
      throw new InvalidGrantError("Invalid or expired authorization grant");
    }
    const [rotated] = await this.db
      .update(oauthTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(oauthTokens.id, stored.id), isNull(oauthTokens.revokedAt)))
      .returning({ id: oauthTokens.id });
    if (!rotated) throw new InvalidGrantError("Invalid or expired authorization grant");
    // A refresh may narrow scopes, never widen them.
    const nextScopes = scopes?.length
      ? scopes.filter((scope) => stored.scopes.includes(scope))
      : stored.scopes;
    return this.issueTokenPair(stored.connectionId, client.client_id, nextScopes, stored.familyId);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const [stored] = await this.db
      .select({
        token: oauthTokens,
        connection: connections,
      })
      .from(oauthTokens)
      .innerJoin(connections, eq(connections.id, oauthTokens.connectionId))
      .where(
        and(
          eq(oauthTokens.hash, digest(token)),
          eq(oauthTokens.type, "access"),
          gt(oauthTokens.expiresAt, new Date())
        )
      )
      .limit(1);
    if (!stored || stored.token.revokedAt) throw new InvalidTokenError("invalid_token");
    if (stored.connection.revokedAt || connectionExpiresAt(stored.connection.createdAt) <= new Date()) {
      throw new InvalidTokenError("connection_revoked");
    }
    return {
      token,
      clientId: stored.token.clientId,
      scopes: stored.token.scopes,
      expiresAt: Math.floor(stored.token.expiresAt.getTime() / 1000),
      resource: new URL(stored.token.resource ?? this.options.resource.href),
      extra: {
        connectionId: stored.connection.id,
        userId: stored.connection.userId,
      },
    };
  }

  /** RFC 7009: a client may only revoke its own tokens. Revoking a refresh token ends the grant. */
  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest) {
    const [stored] = await this.db
      .select({ type: oauthTokens.type, familyId: oauthTokens.familyId })
      .from(oauthTokens)
      .where(and(eq(oauthTokens.hash, digest(request.token)), eq(oauthTokens.clientId, client.client_id)))
      .limit(1);
    if (!stored) return; // unknown tokens are not an error (RFC 7009 §2.2)
    if (stored.type === "refresh") {
      await this.revokeFamily(stored.familyId);
      return;
    }
    await this.db
      .update(oauthTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(oauthTokens.hash, digest(request.token)), isNull(oauthTokens.revokedAt)));
  }

  private async revokeFamily(familyId: string) {
    await this.db
      .update(oauthTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(oauthTokens.familyId, familyId), isNull(oauthTokens.revokedAt)));
  }

  private async revokeConnectionTokens(connectionId: string) {
    await this.db
      .update(oauthTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(oauthTokens.connectionId, connectionId), isNull(oauthTokens.revokedAt)));
  }

  /** The signed-in user's live connections, for a "Connected apps" page. */
  async listConnections(userId: string) {
    const rows = await this.db
      .select({
        id: connections.id,
        clientId: connections.clientId,
        clientName: oauthClients.name,
        scopes: connections.scopes,
        createdAt: connections.createdAt,
      })
      .from(connections)
      .innerJoin(oauthClients, eq(oauthClients.id, connections.clientId))
      .where(and(eq(connections.userId, userId), isNull(connections.revokedAt)))
      .orderBy(connections.createdAt);
    const now = new Date();
    return rows
      .map((row) => ({ ...row, expiresAt: connectionExpiresAt(row.createdAt) }))
      .filter((row) => row.expiresAt > now);
  }

  /** For your settings page: "Disconnect <AI app>". */
  async revokeConnection(connectionId: string, userId: string) {
    const [revoked] = await this.db
      .update(connections)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(connections.id, connectionId),
          eq(connections.userId, userId),
          isNull(connections.revokedAt)
        )
      )
      .returning({ id: connections.id });
    if (!revoked) return false;
    await this.revokeConnectionTokens(connectionId);
    return true;
  }

  /** Deletes expired state so tables stay bounded. Run periodically (server.ts does, hourly). */
  async purgeExpired() {
    const now = new Date();
    await this.db.delete(oauthAuthorizationRequests).where(lt(oauthAuthorizationRequests.expiresAt, now));
    // Consumed codes are kept until expiry so a replay is still detected.
    await this.db.delete(oauthCodes).where(lt(oauthCodes.expiresAt, now));
    // Revoked refresh tokens are kept until they'd have expired, so a stolen
    // copy presented later still triggers reuse detection.
    await this.db.delete(oauthTokens).where(lt(oauthTokens.expiresAt, now));
    await this.db.delete(rateLimits).where(lt(rateLimits.expiresAt, now));
    // Ended connections (revoked, or past their maximum age) and their audit trail.
    await this.db
      .delete(connections)
      .where(
        or(
          lt(connections.revokedAt, sql`now() - interval '${sql.raw(String(TOOL_ACTIVITY_DAYS))} days'`),
          lt(connections.createdAt, sql`now() - interval '${sql.raw(String(CONNECTION_MAX_AGE_SECONDS / 86400 + TOOL_ACTIVITY_DAYS))} days'`)
        )
      );
    await this.db
      .delete(toolActivity)
      .where(lt(toolActivity.createdAt, sql`now() - interval '${sql.raw(String(TOOL_ACTIVITY_DAYS))} days'`));
    // Clients (DCR registrations, cached CIMD documents) nobody connected with.
    await this.db.execute(sql`
      DELETE FROM oauth_clients c
      WHERE c.created_at < now() - interval '${sql.raw(String(UNUSED_CLIENT_DAYS))} days'
        AND NOT EXISTS (SELECT 1 FROM connections WHERE client_id = c.id)
        AND NOT EXISTS (SELECT 1 FROM oauth_authorization_requests WHERE client_id = c.id)
    `);
  }

  private async issueTokenPair(
    connectionId: string,
    clientId: string,
    scopes: string[],
    existingFamilyId?: string
  ): Promise<OAuthTokens> {
    const [connection] = await this.db
      .select()
      .from(connections)
      .where(and(eq(connections.id, connectionId), isNull(connections.revokedAt)))
      .limit(1);
    if (!connection) throw new InvalidGrantError("Invalid or expired authorization grant");
    const endsAt = connectionExpiresAt(connection.createdAt).getTime();
    if (endsAt <= Date.now()) throw new InvalidGrantError("Connection expired; reconnect");
    const accessToken = randomBytes(32).toString("base64url");
    const refreshToken = randomBytes(48).toString("base64url");
    const familyId = existingFamilyId ?? randomUUID();
    const now = Date.now();
    // Every token is bound to our /mcp, whether or not the client sent `resource`.
    const shared = { connectionId, clientId, familyId, scopes, resource: this.options.resource.href };
    await this.db.insert(oauthTokens).values([
      {
        ...shared,
        hash: digest(accessToken),
        type: "access",
        expiresAt: new Date(Math.min(now + ACCESS_TOKEN_SECONDS * 1000, endsAt)),
      },
      {
        ...shared,
        hash: digest(refreshToken),
        type: "refresh",
        expiresAt: new Date(Math.min(now + REFRESH_TOKEN_SECONDS * 1000, endsAt)),
      },
    ]);
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.max(1, Math.floor((Math.min(now + ACCESS_TOKEN_SECONDS * 1000, endsAt) - now) / 1000)),
      refresh_token: refreshToken,
      scope: scopes.join(" "),
    };
  }
}
