import { randomBytes, randomUUID, createHash, timingSafeEqual } from "node:crypto";
import type { Response } from "express";
import { and, eq, gt, isNull } from "drizzle-orm";
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
  InvalidGrantError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { Database } from "../../db/client.js";
import {
  connections,
  oauthAuthorizationRequests,
  oauthClients,
  oauthCodes,
  oauthTokens,
} from "../schema.js";

const ACCESS_TOKEN_SECONDS = 15 * 60;
const REFRESH_TOKEN_SECONDS = 30 * 24 * 60 * 60;
const AUTHORIZATION_REQUEST_SECONDS = 10 * 60;
const CODE_SECONDS = 5 * 60;

function digest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function constantTimeEqual(left: string, right: string) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export type PendingAuthorization = {
  requestId: string;
  clientName: string;
  scopes: string[];
};

/**
 * OAuth 2.1 authorization server backed by Postgres, implementing the MCP SDK's
 * provider interface. The SDK handles the HTTP side (/authorize, /token,
 * /register, /revoke, .well-known metadata); this class stores and checks state.
 *
 * Flow: Claude registers → /authorize stores a pending request and redirects
 * the user to the consent page → the user approves → consent() mints a one-time
 * code → Claude exchanges it (with its PKCE verifier) for access + refresh tokens.
 */
export class PostgresOAuthProvider implements OAuthServerProvider {
  // PKCE is checked inside exchangeAuthorizationCode with a constant-time compare.
  readonly skipLocalPkceValidation = true;
  readonly clientsStore: OAuthRegisteredClientsStore;

  constructor(
    private readonly db: Database,
    /** Where /authorize sends the user to approve. Gets ?requestId=… appended. */
    private readonly consentUrl: URL,
    private readonly supportedScopes: string[]
  ) {
    this.clientsStore = {
      getClient: async (clientId) => {
        const [client] = await db
          .select()
          .from(oauthClients)
          .where(eq(oauthClients.id, clientId))
          .limit(1);
        return client?.metadata as OAuthClientInformationFull | undefined;
      },
      // The SDK has already issued a client_secret when the client asked for
      // client_secret_post. Keep the client's chosen auth method so the
      // registration response never says "none" while also requiring a secret.
      registerClient: async (metadata) => {
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

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    response: Response
  ) {
    const requested = params.scopes?.length ? params.scopes : this.supportedScopes;
    const scopes = requested.filter((scope) => this.supportedScopes.includes(scope));
    const requestId = randomBytes(24).toString("base64url");
    await this.db.insert(oauthAuthorizationRequests).values({
      requestId,
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      state: params.state ?? null,
      codeChallenge: params.codeChallenge,
      scopes,
      resource: params.resource?.toString() ?? null,
      expiresAt: new Date(Date.now() + AUTHORIZATION_REQUEST_SECONDS * 1000),
    });
    const consent = new URL(this.consentUrl);
    consent.searchParams.set("requestId", requestId);
    response.redirect(consent.toString());
  }

  /** What the consent page needs to show: who is asking and for which scopes. */
  async pendingAuthorization(requestId: string): Promise<PendingAuthorization | undefined> {
    const [pending] = await this.db
      .select({
        requestId: oauthAuthorizationRequests.requestId,
        scopes: oauthAuthorizationRequests.scopes,
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
    return pending;
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
    const redirect = new URL(pending.redirectUri);
    redirect.searchParams.set("code", code);
    if (pending.state) redirect.searchParams.set("state", pending.state);
    return redirect.toString();
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
    const redirect = new URL(pending.redirectUri);
    redirect.searchParams.set("error", "access_denied");
    if (pending.state) redirect.searchParams.set("state", pending.state);
    return redirect.toString();
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
    if (!stored || !codeVerifier || stored.redirectUri !== redirectUri) {
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
    return this.issueTokenPair(
      stored.connectionId,
      client.client_id,
      stored.scopes,
      resource?.toString() ?? stored.resource ?? undefined
    );
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
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
      // A rotated refresh token came back: someone holds a stolen copy.
      // Kill every token from this consent so both copies stop working.
      await this.db
        .update(oauthTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(oauthTokens.familyId, stored.familyId), isNull(oauthTokens.revokedAt)));
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
    return this.issueTokenPair(
      stored.connectionId,
      client.client_id,
      nextScopes,
      resource?.toString() ?? stored.resource ?? undefined,
      stored.familyId
    );
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
    if (stored.connection.revokedAt) throw new InvalidTokenError("connection_revoked");
    return {
      token,
      clientId: stored.token.clientId,
      scopes: stored.token.scopes,
      expiresAt: Math.floor(stored.token.expiresAt.getTime() / 1000),
      ...(stored.token.resource ? { resource: new URL(stored.token.resource) } : {}),
      extra: {
        connectionId: stored.connection.id,
        userId: stored.connection.userId,
      },
    };
  }

  async revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest) {
    await this.db
      .update(oauthTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(oauthTokens.hash, digest(request.token)), isNull(oauthTokens.revokedAt)));
  }

  /** For your settings page: "Disconnect Claude". */
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
    await this.db
      .update(oauthTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(oauthTokens.connectionId, connectionId), isNull(oauthTokens.revokedAt)));
    return true;
  }

  private async issueTokenPair(
    connectionId: string,
    clientId: string,
    scopes: string[],
    resource?: string,
    existingFamilyId?: string
  ): Promise<OAuthTokens> {
    const [connection] = await this.db
      .select()
      .from(connections)
      .where(and(eq(connections.id, connectionId), isNull(connections.revokedAt)))
      .limit(1);
    if (!connection) throw new InvalidGrantError("Invalid or expired authorization grant");
    const accessToken = randomBytes(32).toString("base64url");
    const refreshToken = randomBytes(48).toString("base64url");
    const familyId = existingFamilyId ?? randomUUID();
    const now = Date.now();
    const shared = { connectionId, clientId, familyId, scopes, resource: resource ?? null };
    await this.db.insert(oauthTokens).values([
      {
        ...shared,
        hash: digest(accessToken),
        type: "access",
        expiresAt: new Date(now + ACCESS_TOKEN_SECONDS * 1000),
      },
      {
        ...shared,
        hash: digest(refreshToken),
        type: "refresh",
        expiresAt: new Date(now + REFRESH_TOKEN_SECONDS * 1000),
      },
    ]);
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_SECONDS,
      refresh_token: refreshToken,
      scope: scopes.join(" "),
    };
  }
}
