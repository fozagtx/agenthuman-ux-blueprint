import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createDatabase } from "./db/client.js";

const config = loadConfig();
const { db, pool } = createDatabase();
const { app, provider } = createApp(db, config);

const server = app.listen(config.port, () => {
  console.log(`MCP server: ${new URL("/mcp", config.apiUrl)}`);
  if (config.devLogin) console.log("DEV_LOGIN is on — do not use in production");
});

// Expired codes, tokens, sign-in requests and rate-limit windows.
const purge = setInterval(() => {
  provider.purgeExpired().catch((error: unknown) => console.error("purgeExpired", error));
}, 60 * 60 * 1000);
purge.unref();

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close(() => void pool.end());
  });
}
