import { desc, eq } from "drizzle-orm";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";
import type { Database } from "../../db/client.js";
import { toolActivity } from "../../mcp-kit/schema.js";
import { logTool, resolveToolContext, result } from "../../mcp-kit/index.js";
import { users } from "../schema.js";

/** Tools about the connection itself. Useful in any project. */
export function registerAccountTools(server: McpServer, db: Database) {
  server.registerTool(
    "whoami",
    {
      title: "Who am I",
      description: "Get the account this connection acts for and the scopes it was granted.",
      annotations: { readOnlyHint: true },
    },
    async (extra) => {
      const { context, error } = await resolveToolContext(db, extra.authInfo, "notes:read");
      if (error) return result(error, true);
      const [user] = await db
        .select({ email: users.email })
        .from(users)
        .where(eq(users.id, context.userId))
        .limit(1);
      await logTool(db, context.connectionId, "whoami", {}, "allowed");
      return result({ email: user?.email ?? null, scopes: context.scopes });
    }
  );

  server.registerTool(
    "get_activity",
    {
      title: "Recent activity",
      description: "List the recent tool calls made through this connection.",
      inputSchema: { limit: z.number().int().min(1).max(100).default(20) },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const { context, error } = await resolveToolContext(db, extra.authInfo, "notes:read");
      if (error) return result(error, true);
      const rows = await db
        .select({
          tool: toolActivity.tool,
          decision: toolActivity.decision,
          error: toolActivity.error,
          createdAt: toolActivity.createdAt,
        })
        .from(toolActivity)
        .where(eq(toolActivity.connectionId, context.connectionId))
        .orderBy(desc(toolActivity.createdAt))
        .limit(args.limit);
      return result({ activity: rows });
    }
  );
}
