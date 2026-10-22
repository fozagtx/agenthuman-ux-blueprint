import * as kit from "../mcp-kit/schema.js";
import * as project from "../project/schema.js";

/** Every table, for drizzle's typed query builder. */
export const schema = { ...kit, ...project };
