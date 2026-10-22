import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { Database } from "../../db/client.js";
import { resolveToolContext } from "../../mcp-kit/index.js";
import type { Scope } from "../scopes.js";

/**
 * resolveToolContext, typed to this project's scopes: a tool asking for a
 * scope that isn't in scopes.ts (a typo, or one you renamed) fails typecheck.
 */
export function toolContext(db: Database, auth: AuthInfo | undefined, scope: Scope | null) {
  return resolveToolContext(db, auth, scope);
}
