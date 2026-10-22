export interface Config {
  /** Public origin of this server. It is the OAuth issuer and hosts /mcp. */
  apiUrl: string;
  port: number;
  sessionSecret: string;
  devLogin: boolean;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const port = Number(env.PORT ?? 4000);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new RangeError("PORT must be a valid TCP port");
  }
  const sessionSecret = env.SESSION_SECRET ?? "";
  if (sessionSecret.length < 32) {
    throw new Error("SESSION_SECRET must be at least 32 characters");
  }
  return {
    apiUrl: env.PUBLIC_API_URL ?? env.RENDER_EXTERNAL_URL ?? `http://localhost:${port}`,
    port,
    sessionSecret,
    devLogin: env.DEV_LOGIN === "true",
  };
}
