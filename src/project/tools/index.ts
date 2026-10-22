import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Database } from "../../db/client.js";
import { registerAccountTools } from "./account.js";
import { registerNoteTools } from "./notes.js";

/**
 * YOUR TOOLS. One file per area of your project (catalog, cart,
 * orders…), each exporting a register function that is called here.
 *
 * Every tool follows the same three steps:
 *   1. resolveToolContext(db, extra.authInfo, "<scope>") → who, and allowed?
 *   2. do the work, always filtered by context.userId
 *   3. logTool(...) and return result(...)
 *
 * Write descriptions for the model: say what the tool does, when to use it,
 * and what each argument means. That text is how Claude picks tools.
 */
export function registerTools(server: McpServer, db: Database) {
  registerAccountTools(server, db);
  registerNoteTools(server, db);
}
