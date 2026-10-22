import { and, eq, isNull, sql } from "drizzle-orm";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { Database } from "../../db/client.js";
import { connections, toolActivity } from "../schema.js";

const CALLS_PER_MINUTE = 120;

export type ToolContext = {
  userId: string;
  connectionId: string;
  scopes: string[];
};

/** Tool result in the shape MCP clients expect: text for the model, JSON for apps. */
export function result(value: Record<string, unknown>, isError = false) {
  const serialized = JSON.stringify(value, (_key, item) =>
    typeof item === "bigint" ? item.toString() : item
  );
  return {
    content: [{ type: "text" as const, text: serialized }],
    structuredContent: JSON.parse(serialized) as Record<string, unknown>,
    ...(isError ? { isError: true } : {}),
  };
}

async function consumeRateLimit(db: Database, connectionId: string) {
  const key = `mcp-connection:${connectionId}`;
  const rows = await db.execute(sql`
    INSERT INTO rate_limits (key, window_started_at, count, expires_at)
    VALUES (${key}, now(), 1, now() + interval '1 minute')
    ON CONFLICT (key) DO UPDATE SET
      count = CASE WHEN rate_limits.expires_at <= now() THEN 1 ELSE rate_limits.count + 1 END,
      window_started_at = CASE WHEN rate_limits.expires_at <= now() THEN now() ELSE rate_limits.window_started_at END,
      expires_at = CASE WHEN rate_limits.expires_at <= now() THEN now() + interval '1 minute' ELSE rate_limits.expires_at END
    RETURNING count
  `);
  return Number(rows.rows[0]?.count ?? 0) <= CALLS_PER_MINUTE;
}

/**
 * Every tool starts here. Turns the verified bearer token into "which user,
 * through which connection", re-checks the connection is still live, applies
 * the rate limit and the scope the tool needs.
 */
export async function resolveToolContext(
  db: Database,
  auth: AuthInfo | undefined,
  requiredScope: string
): Promise<{ context: ToolContext; error?: never } | { context?: never; error: Record<string, unknown> }> {
  const connectionId = String(auth?.extra?.connectionId ?? "");
  if (!auth || !connectionId) return { error: { code: "connection_revoked" } };
  if (!auth.scopes.includes(requiredScope)) {
    return { error: { code: "insufficient_scope", required: requiredScope } };
  }
  if (!(await consumeRateLimit(db, connectionId))) {
    return { error: { code: "rate_limited", retry_after_seconds: 60 } };
  }
  const [connection] = await db
    .select({ userId: connections.userId })
    .from(connections)
    .where(and(eq(connections.id, connectionId), isNull(connections.revokedAt)))
    .limit(1);
  if (!connection) return { error: { code: "connection_revoked" } };
  return { context: { userId: connection.userId, connectionId, scopes: auth.scopes } };
}

export async function logTool(
  db: Database,
  connectionId: string,
  tool: string,
  args: Record<string, unknown>,
  decision: "allowed" | "rejected" | "error",
  error?: string
) {
  await db.insert(toolActivity).values({
    connectionId,
    tool,
    argsJson: args,
    decision,
    error: error ?? null,
  });
}
