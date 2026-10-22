import express from "express";
import { sql } from "drizzle-orm";
import type { Config } from "./config.js";
import type { Database } from "./db/client.js";
import { createMcpKit } from "./mcp-kit/index.js";
import { createDevLoginRouter } from "./project/dev-login.js";
import { BRANDING } from "./project/branding.js";
import { SCOPES } from "./project/scopes.js";
import { createCookieSession } from "./project/session.js";
import { registerTools } from "./project/tools/index.js";

/** Wires the kit to your project. This is the only file that knows both. */
export function createApp(db: Database, config: Config) {
  const app = express();
  app.disable("x-powered-by");
  // Behind Render/Fly/Railway/Cloudflare the TLS ends at a proxy.
  app.set("trust proxy", 1);

  const session = createCookieSession(config.sessionSecret, config.apiUrl.startsWith("https://"));

  const mcp = createMcpKit({
    db,
    apiUrl: config.apiUrl,
    secret: config.sessionSecret,
    session,
    branding: BRANDING,
    scopes: SCOPES,
    registerTools,
    serverInfo: { name: "agenthuman-ux", version: "0.1.0" },
  });
  app.use(mcp.router);

  if (config.devLogin) app.use(createDevLoginRouter(db, session, BRANDING));

  app.get("/health", async (_request, response, next) => {
    try {
      await db.execute(sql`SELECT 1`);
      response.json({ ok: true });
    } catch (error) {
      next(error);
    }
  });

  app.use(
    (error: unknown, request: express.Request, response: express.Response, next: express.NextFunction) => {
      void next;
      const message = error instanceof Error ? error.message : String(error);
      if (message === "invalid_consent") {
        response.status(400).json({ error: message });
        return;
      }
      console.error(`${request.method} ${request.path}`, error);
      response.status(500).json({ error: "internal_error" });
    }
  );

  return app;
}
