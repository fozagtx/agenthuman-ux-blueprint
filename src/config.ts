export interface Config {
  /** Public origin of this server. It is the OAuth issuer and hosts /mcp. */
  apiUrl: string;
  port: number;
  sessionSecret: string;
  devLogin: boolean;
  /** Proxy hops in front of the server (Express `trust proxy`). 0 when exposed directly. */
  trustProxy: number;
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
  const devLogin = env.DEV_LOGIN === "true";
  // The dev login signs anyone in as any email. Refuse to boot with it in production.
  if (devLogin && env.NODE_ENV === "production") {
    throw new Error("DEV_LOGIN=true is not allowed when NODE_ENV=production");
  }
  const trustProxy = Number(env.TRUST_PROXY ?? 1);
  if (!Number.isInteger(trustProxy) || trustProxy < 0) {
    throw new RangeError("TRUST_PROXY must be a whole number of proxy hops");
  }
  return {
    apiUrl: env.PUBLIC_API_URL ?? env.RENDER_EXTERNAL_URL ?? `http://localhost:${port}`,
    port,
    sessionSecret,
    devLogin,
    trustProxy,
  };
}
