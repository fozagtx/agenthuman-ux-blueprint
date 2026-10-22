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
 * The URL comes from whoever calls /authorize, unauthenticated, so the fetch
 * is hardened against SSRF and abuse:
 *   - https on port 443 only; public addresses only, checked at connect time
 *     (DNS rebinding can't swap the address) and for IP-literal hosts in any
 *     IPv6 spelling (mapped, compatible, NAT64, 6to4, Teredo)
 *   - no redirects, 5 s total deadline, 64 KB cap
 *   - at most 16 fetches in flight, one per URL at a time, failures cached 60 s
 *   - the client only ever sees "could not fetch"; the cause is logged here,
 *     so the endpoint can't be used to scan an internal network
 */

const DEADLINE_MS = 5_000;
const MAX_BYTES = 64 * 1024;
const MAX_IN_FLIGHT = 16;
const FAILURE_CACHE_MS = 60_000;
const FAILURE_CACHE_SIZE = 1_000;

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

function isPublicIPv4(address: string) {
  const [a, b, c] = address.split(".").map(Number) as [number, number, number];
  return !(
    a === 0 || a === 10 || a === 127 || a >= 224 || // this-network, private, loopback, multicast+reserved
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    (a === 169 && b === 254) || // link-local, cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) || // IETF protocol, TEST-NET-1
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  );
}

/** Any IPv6 text form → its 8 16-bit groups. */
function ipv6Groups(address: string): number[] {
  let text = address.toLowerCase().split("%")[0]!;
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number) as [number, number, number, number];
    text = `${text.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = text.split("::") as [string, string | undefined];
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups = tail === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  return groups.map((group) => parseInt(group, 16));
}

const embeddedIPv4 = (high: number, low: number) =>
  `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;

/** False for loopback, private, link-local, CGNAT, multicast and reserved space, in any notation. */
export function isPublicAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return isPublicIPv4(address);
  if (version !== 6) return false;
  const g = ipv6Groups(address);
  const zero = (from: number, to: number) => g.slice(from, to).every((group) => group === 0);
  if (zero(0, 5) && g[5] === 0xffff) return isPublicIPv4(embeddedIPv4(g[6]!, g[7]!)); // ::ffff:a.b.c.d
  if (zero(0, 6)) return false; // ::, ::1, deprecated ::a.b.c.d
  if (g[0] === 0x64 && g[1] === 0xff9b) {
    return zero(2, 6) && isPublicIPv4(embeddedIPv4(g[6]!, g[7]!)); // NAT64; 64:ff9b:1::/48 is local
  }
  if (g[0] === 0x2002) return isPublicIPv4(embeddedIPv4(g[1]!, g[2]!)); // 6to4
  if (g[0] === 0x2001 && (g[1] === 0 || g[1] === 0xdb8)) return false; // Teredo, documentation
  const first = g[0]!;
  return !(
    (first & 0xfe00) === 0xfc00 || // unique local
    (first & 0xffc0) === 0xfe80 || // link-local
    (first & 0xffc0) === 0xfec0 || // site-local
    (first & 0xff00) === 0xff00 // multicast
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

let inFlight = 0;

function fetchJson(url: URL, options: ClientMetadataOptions): Promise<unknown> {
  const loopback = url.protocol === "http:";
  if (!loopback && url.port !== "" && url.port !== "443") {
    return Promise.reject(new Error("client metadata must be served on port 443"));
  }
  // Node skips `lookup` for IP-literal hosts, so check those directly.
  const literal = url.hostname.replace(/^\[|\]$/g, "");
  if (!loopback && isIP(literal) && !isPublicAddress(literal)) {
    return Promise.reject(new Error("client metadata host is not public"));
  }
  if (inFlight >= MAX_IN_FLIGHT) return Promise.reject(new Error("too many client metadata fetches"));
  inFlight += 1;
  const client = loopback ? http : https;
  return new Promise<unknown>((resolve, reject) => {
    const request = client.get(
      url,
      {
        headers: { accept: "application/json" },
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
        response.on("error", reject);
      }
    );
    // A total deadline: `timeout` alone only fires on an idle socket, so a
    // server trickling one byte every few seconds could hold it for hours.
    const deadline = setTimeout(
      () => request.destroy(new Error("client metadata fetch timed out")),
      DEADLINE_MS
    );
    request.on("close", () => clearTimeout(deadline));
    request.on("error", reject);
  }).finally(() => {
    inFlight -= 1;
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
const pending = new Map<string, Promise<OAuthClientInformationFull>>();
const failures = new Map<string, { error: InvalidClientError; until: number }>();

export function fetchClientMetadata(
  clientId: string,
  options: ClientMetadataOptions = {}
): Promise<OAuthClientInformationFull> {
  const failed = failures.get(clientId);
  if (failed && failed.until > Date.now()) return Promise.reject(failed.error);
  const existing = pending.get(clientId);
  if (existing) return existing;
  const attempt = loadClientMetadata(clientId, options)
    .catch((error: unknown) => {
      const clientError =
        error instanceof InvalidClientError ? error : new InvalidClientError("Invalid client metadata");
      if (failures.size >= FAILURE_CACHE_SIZE) failures.clear();
      failures.set(clientId, { error: clientError, until: Date.now() + FAILURE_CACHE_MS });
      throw clientError;
    })
    .finally(() => pending.delete(clientId));
  pending.set(clientId, attempt);
  return attempt;
}

async function loadClientMetadata(
  clientId: string,
  options: ClientMetadataOptions
): Promise<OAuthClientInformationFull> {
  let document: unknown;
  try {
    document = await fetchJson(new URL(clientId), options);
  } catch (cause) {
    // Never echo the network error: it would tell a caller which internal
    // hosts and ports exist.
    console.warn(`CIMD fetch failed for ${clientId}:`, cause instanceof Error ? cause.message : cause);
    throw new InvalidClientError("Could not fetch client metadata");
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
