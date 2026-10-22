import { sql } from "drizzle-orm";
import {
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
// The kit's only link to your data model: connections belong to your users.
import { users } from "../project/schema.js";

const createdAt = () =>
  timestamp("created_at", { withTimezone: true }).notNull().defaultNow();

const scopes = () =>
  text("scopes").array().notNull().default(sql`ARRAY[]::text[]`);

/**
 * What the user approves on the consent page: "this AI client may act for me
 * with these scopes". Every token belongs to one, so revoking it cuts the
 * client off immediately. (StellaBox calls this a "grant" and adds spend caps.)
 */
export const connections = pgTable(
  "connections",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClients.id, { onDelete: "cascade" }),
    scopes: scopes(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [index("connections_user_id_idx").on(table.userId)]
);

// OAuth 2.1 state. Codes and tokens are stored as SHA-256 hashes only.

export const oauthClients = pgTable("oauth_clients", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  redirectUris: text("redirect_uris").array().notNull(),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull(),
  registeredAt: createdAt(),
});

export const oauthAuthorizationRequests = pgTable(
  "oauth_authorization_requests",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    requestId: text("request_id").notNull(),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClients.id, { onDelete: "cascade" }),
    userId: uuid("user_id").references(() => users.id, { onDelete: "cascade" }),
    redirectUri: text("redirect_uri").notNull(),
    state: text("state"),
    codeChallenge: text("code_challenge").notNull(),
    scopes: scopes(),
    resource: text("resource"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [
    uniqueIndex("oauth_authorization_requests_request_id_idx").on(table.requestId),
  ]
);

export const oauthCodes = pgTable(
  "oauth_codes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    codeHash: text("code_hash").notNull(),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClients.id, { onDelete: "cascade" }),
    connectionId: uuid("connection_id")
      .notNull()
      .references(() => connections.id, { onDelete: "cascade" }),
    redirectUri: text("redirect_uri").notNull(),
    codeChallenge: text("code_challenge").notNull(),
    scopes: scopes(),
    resource: text("resource"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [uniqueIndex("oauth_codes_code_hash_idx").on(table.codeHash)]
);

export const oauthTokens = pgTable(
  "oauth_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    connectionId: uuid("connection_id")
      .notNull()
      .references(() => connections.id, { onDelete: "cascade" }),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClients.id, { onDelete: "cascade" }),
    hash: text("hash").notNull(),
    type: text("type").$type<"access" | "refresh">().notNull(),
    // Refresh tokens rotate; every token from one consent shares a family.
    familyId: uuid("family_id").notNull(),
    scopes: scopes(),
    resource: text("resource"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [
    uniqueIndex("oauth_tokens_hash_idx").on(table.hash),
    index("oauth_tokens_family_id_idx").on(table.familyId),
  ]
);

/** Audit log of every tool call. */
export const toolActivity = pgTable(
  "tool_activity",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    connectionId: uuid("connection_id")
      .notNull()
      .references(() => connections.id, { onDelete: "cascade" }),
    tool: text("tool").notNull(),
    argsJson: jsonb("args_json").$type<Record<string, unknown>>().notNull(),
    decision: text("decision").notNull(),
    error: text("error"),
    createdAt: createdAt(),
  },
  (table) => [index("tool_activity_connection_id_idx").on(table.connectionId)]
);

/** Fixed one-minute windows, keyed by connection. */
export const rateLimits = pgTable("rate_limits", {
  key: text("key").primaryKey(),
  windowStartedAt: timestamp("window_started_at", { withTimezone: true }).notNull(),
  count: integer("count").notNull().default(0),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
});
