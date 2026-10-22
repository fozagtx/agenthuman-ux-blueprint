import { desc, eq } from "drizzle-orm";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";
import type { Database } from "../../db/client.js";
import { toolActivity } from "../../mcp-kit/schema.js";
import { logTool, result } from "../../mcp-kit/index.js";
import { users } from "../schema.js";
import { toolContext } from "./context.js";

/**
 * Tools about the connection itself. Useful in any project, and need no
 * scope: any live connection may call them, so renaming scopes can't break them.
 */
export function registerAccountTools(server: McpServer, db: Database) {
  // A profile tool, in the shape ChatGPT uses to tell several connected
  // accounts apart (`_meta["openai/profile"]`, strict output schema). Other
  // clients just see an ordinary read-only tool.
  server.registerTool(
    "whoami",
    {
      title: "Who am I",
      description:
        "Return the account this connection acts for. The id is opaque, unique in this app, and stays the same across reconnections.",
      inputSchema: z.strictObject({}),
      outputSchema: z.strictObject({
        id: z.string().min(1).describe("Opaque, stable account id. Never an email."),
        email: z.string().optional().describe("For display only."),
      }),
      annotations: { readOnlyHint: true },
      _meta: { "openai/profile": true },
    },
    async (_args, extra) => {
      const { context, error } = await toolContext(db, extra.authInfo, null);
      if (error) return result(error, true);
      const [user] = await db
        .select({ email: users.email })
        .from(users)
        .where(eq(users.id, context.userId))
        .limit(1);
      await logTool(db, context.connectionId, "whoami", {}, "allowed");
      return result({ id: context.userId, ...(user ? { email: user.email } : {}) });
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
      const { context, error } = await toolContext(db, extra.authInfo, null);
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
