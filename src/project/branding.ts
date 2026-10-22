import { fileURLToPath } from "node:url";
import type { Branding } from "../mcp-kit/index.js";

/**
 * How your connector looks. Edit the defaults here, or override per deployment
 * with env vars so one codebase can run under several brands.
 *
 * - name:        consent page heading ("Connect Claude to <name>") and the
 *                server title MCP clients display
 * - faviconPath: served at /favicon.ico and /favicon.<ext>; Claude shows the
 *                connector's icon from it. .svg, .png or .ico
 * - accentColor: button colour on the consent and login pages (hex)
 */
export const BRANDING: Branding = {
  name: process.env.BRAND_NAME ?? "AgentHuman UX",
  faviconPath:
    process.env.BRAND_FAVICON_PATH ?? fileURLToPath(new URL("./assets/favicon.svg", import.meta.url)),
  accentColor: process.env.BRAND_ACCENT_COLOR ?? "#4054d6",
};
