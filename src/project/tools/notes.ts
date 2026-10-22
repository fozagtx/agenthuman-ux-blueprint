import { and, desc, eq } from "drizzle-orm";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";
import type { Database } from "../../db/client.js";
import { logTool, result } from "../../mcp-kit/index.js";
import { toolContext } from "./context.js";
import { notes } from "../schema.js";

/** Example tools: one read, one write, one destructive. Replace with yours. */
export function registerNoteTools(server: McpServer, db: Database) {
  server.registerTool(
    "list_notes",
    {
      title: "List notes",
      description: "List the user's most recent notes, newest first.",
      inputSchema: { limit: z.number().int().min(1).max(100).default(20) },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const { context, error } = await toolContext(db, extra.authInfo, "notes:read");
      if (error) return result(error, true);
      const rows = await db
        .select({ id: notes.id, title: notes.title, body: notes.body, createdAt: notes.createdAt })
        .from(notes)
        .where(eq(notes.userId, context.userId))
        .orderBy(desc(notes.createdAt))
        .limit(args.limit);
      await logTool(db, context.connectionId, "list_notes", args, "allowed");
      return result({ notes: rows });
    }
  );

  server.registerTool(
    "create_note",
    {
      title: "Create note",
      description: "Save a new note for the user.",
      inputSchema: {
        title: z.string().min(1).max(200),
        body: z.string().max(10_000),
      },
    },
    async (args, extra) => {
      const { context, error } = await toolContext(db, extra.authInfo, "notes:write");
      if (error) return result(error, true);
      const [note] = await db
        .insert(notes)
        .values({ userId: context.userId, title: args.title, body: args.body })
        .returning({ id: notes.id, createdAt: notes.createdAt });
      await logTool(db, context.connectionId, "create_note", { title: args.title }, "allowed");
      return result({ note });
    }
  );

  server.registerTool(
    "delete_note",
    {
      title: "Delete note",
      description: "Permanently delete one of the user's notes by id. Confirm with the user first.",
      inputSchema: { note_id: z.string().uuid() },
      annotations: { destructiveHint: true },
    },
    async (args, extra) => {
      const { context, error } = await toolContext(db, extra.authInfo, "notes:write");
      if (error) return result(error, true);
      // Always filter by userId: an id alone must never reach another user's data.
      const [deleted] = await db
        .delete(notes)
        .where(and(eq(notes.id, args.note_id), eq(notes.userId, context.userId)))
        .returning({ id: notes.id });
      if (!deleted) {
        await logTool(db, context.connectionId, "delete_note", args, "rejected", "note_not_found");
        return result({ code: "note_not_found" }, true);
      }
      await logTool(db, context.connectionId, "delete_note", args, "allowed");
      return result({ deleted: deleted.id });
    }
  );
}
