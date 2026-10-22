import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import { InvalidClientError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

/**
 * OAuth Client ID Metadata Documents (CIMD), the registration method the MCP
 * spec now prefers over dynamic client registration. The client's id is an
 * HTTPS URL (ChatGPT: https://chatgpt.com/oauth/client.json, Claude Code:
 * https://claude.ai/oauth/claude-code-client-metadata) and we fetch the JSON
 * document at that URL to learn its name and redirect URIs.
 *
 * Because the URL comes from whoever calls /authorize, the fetch is hardened
 * against SSRF: HTTPS only, public IPs only (checked at connect time, so DNS
 * rebinding can't swap the address), no redirects, 5 s timeout, 64 KB cap.
 */

const TIMEOUT_MS = 5_000;
const MAX_BYTES = 64 * 1024;

export type ClientMetadataOptions = {
  /** Dev/test only: also accept http://localhost and http://127.0.0.1 ids. */
  allowLoopback?: boolean;
};

export function isClientMetadataUrl(clientId: string, options: ClientMetadataOptions = {}) {
  if (!URL.canParse(clientId)) return false;
  const url = new URL(clientId);
  if (url.hash || url.username || url.password || url.pathname === "/") return false;
  if (url.protocol === "https:") return true;
  return Boolean(options.allowLoopback) && url.protocol === "http:" && isLoopbackHost(url.hostname);
}

function isLoopbackHost(host: string) {
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
}

/** Private, loopback, link-local, CGNAT, multicast and reserved ranges. */
function isPublicAddress(address: string) {
  if (isIP(address) === 4) {
    const [a, b] = address.split(".").map(Number) as [number, number];
    return !(
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19))
    );
  }
  const v6 = address.toLowerCase();
  if (v6.startsWith("::ffff:")) return isPublicAddress(v6.slice(7));
  return !(
    v6 === "::" || v6 === "::1" ||
    v6.startsWith("fc") || v6.startsWith("fd") || // unique local
    v6.startsWith("fe8") || v6.startsWith("fe9") || v6.startsWith("fea") || v6.startsWith("feb") || // link-local
    v6.startsWith("ff") // multicast
  );
}

type LookupCallback = (error: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/** DNS lookup that refuses to hand non-public addresses to the socket. */
function publicOnlyLookup(hostname: string, options: object, callback: LookupCallback) {
  dnsLookup(hostname, { ...options, all: true }, (error, addresses) => {
    if (error) return callback(error, []);
    const list = addresses as LookupAddress[];
    if (!list.length || !list.every((entry) => isPublicAddress(entry.address))) {
      return callback(Object.assign(new Error("client metadata host is not public"), { code: "EBLOCKED" }), []);
    }
    callback(null, (options as { all?: boolean }).all ? list : list[0]!.address, list[0]!.family);
  });
}

function fetchJson(url: URL, options: ClientMetadataOptions): Promise<unknown> {
  const loopback = url.protocol === "http:";
  const client = loopback ? http : https;
  // Node skips `lookup` for IP-literal hosts, so check those directly.
  const literal = url.hostname.replace(/^\[|\]$/g, "");
  if (!loopback && isIP(literal) && !isPublicAddress(literal)) {
    return Promise.reject(new Error("client metadata host is not public"));
  }
  return new Promise((resolve, reject) => {
    const request = client.get(
      url,
      {
        headers: { accept: "application/json" },
        timeout: TIMEOUT_MS,
        ...(loopback && options.allowLoopback ? {} : { lookup: publicOnlyLookup as never }),
      },
      (response) => {
        if (response.statusCode !== 200) {
          response.resume();
          reject(new Error(`client metadata returned HTTP ${response.statusCode}`));
          return;
        }
        let size = 0;
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_BYTES) {
            request.destroy(new Error("client metadata document too large"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            reject(new Error("client metadata is not valid JSON"));
          }
        });
      }
    );
    request.on("timeout", () => request.destroy(new Error("client metadata fetch timed out")));
    request.on("error", reject);
  });
}

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === "string");

/**
 * Fetches and validates a client's metadata document. We only support public
 * clients for CIMD (PKCE, no secret), so the document must allow
 * token_endpoint_auth_method "none" — either in the plural list (SEP-3149,
 * which ChatGPT publishes) or as the singular value (which Claude publishes).
 */
export async function fetchClientMetadata(
  clientId: string,
  options: ClientMetadataOptions = {}
): Promise<OAuthClientInformationFull> {
  let document: unknown;
  try {
    document = await fetchJson(new URL(clientId), options);
  } catch (cause) {
    throw new InvalidClientError(
      `Could not fetch client metadata: ${cause instanceof Error ? cause.message : String(cause)}`
    );
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new InvalidClientError("Client metadata must be a JSON object");
  }
  const meta = document as Record<string, unknown>;
  if (meta.client_id !== clientId) {
    throw new InvalidClientError("Client metadata client_id does not match its URL");
  }
  if (typeof meta.client_name !== "string" || !meta.client_name.trim()) {
    throw new InvalidClientError("Client metadata is missing client_name");
  }
  if (!isStringArray(meta.redirect_uris) || meta.redirect_uris.length === 0) {
    throw new InvalidClientError("Client metadata is missing redirect_uris");
  }
  for (const uri of meta.redirect_uris) {
    const parsed = URL.canParse(uri) ? new URL(uri) : undefined;
    const allowed =
      parsed?.protocol === "https:" ||
      (parsed?.protocol === "http:" && isLoopbackHost(parsed.hostname));
    if (!allowed) throw new InvalidClientError(`Client metadata redirect_uri not allowed: ${uri}`);
  }
  const methods = isStringArray(meta.token_endpoint_auth_methods_supported)
    ? meta.token_endpoint_auth_methods_supported
    : [];
  const single = typeof meta.token_endpoint_auth_method === "string" ? meta.token_endpoint_auth_method : undefined;
  if (!methods.includes("none") && single !== "none" && !(single === undefined && methods.length === 0)) {
    throw new InvalidClientError("Client must support token_endpoint_auth_method \"none\"");
  }
  if (isStringArray(meta.grant_types) && !meta.grant_types.includes("authorization_code")) {
    throw new InvalidClientError("Client metadata does not allow authorization_code");
  }
  return {
    client_id: clientId,
    client_name: meta.client_name,
    redirect_uris: meta.redirect_uris,
    ...(typeof meta.client_uri === "string" ? { client_uri: meta.client_uri } : {}),
    ...(typeof meta.logo_uri === "string" ? { logo_uri: meta.logo_uri } : {}),
    grant_types: isStringArray(meta.grant_types) ? meta.grant_types : ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  } as OAuthClientInformationFull;
}
