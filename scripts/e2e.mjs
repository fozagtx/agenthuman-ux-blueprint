// Walks the same path Claude takes: discover → register → authorize → consent → token → /mcp.
import { createHash, randomBytes } from "node:crypto";

const base = process.env.BASE_URL ?? "http://localhost:4000";
const redirectUri = "https://claude.ai/api/mcp/auth_callback";
const ok = (cond, label) => { if (!cond) throw new Error(`FAIL: ${label}`); console.log(`ok  ${label}`); };

// 1. Unauthenticated /mcp → 401 with resource metadata pointer
let r = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
ok(r.status === 401 && /resource_metadata=/.test(r.headers.get("www-authenticate") ?? ""), "401 + WWW-Authenticate resource_metadata");

r = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
const prm = await r.json();
ok(prm.resource === `${base}/mcp`, "protected resource metadata");
r = await fetch(`${base}/.well-known/oauth-authorization-server`);
const asm = await r.json();
ok(asm.registration_endpoint && asm.code_challenge_methods_supported.includes("S256"), "authorization server metadata");

// 2. Dynamic client registration
r = await fetch(asm.registration_endpoint, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ client_name: "Claude", redirect_uris: [redirectUri], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }),
});
const client = await r.json();
ok(r.status === 201 && client.client_id, "client registered");

// 3. Authorize with PKCE
const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const auth = new URL(asm.authorization_endpoint);
Object.entries({ response_type: "code", client_id: client.client_id, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256", state: "xyz", scope: "notes:read notes:write", resource: `${base}/mcp` }).forEach(([k, v]) => auth.searchParams.set(k, v));
r = await fetch(auth, { redirect: "manual" });
const connectUrl = new URL(r.headers.get("location"), base);
ok(r.status === 302 && connectUrl.pathname === "/connect", "authorize → /connect");

// 4. Not signed in → login, then sign in
r = await fetch(connectUrl, { redirect: "manual" });
ok(r.status === 302 && r.headers.get("location").startsWith("/login"), "consent requires login");
r = await fetch(`${base}/login`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ email: "test@example.com", next: connectUrl.pathname + connectUrl.search }) });
const cookie = r.headers.get("set-cookie").split(";")[0];
ok(r.status === 303 && r.headers.get("location").startsWith("/connect"), "dev login → back to /connect");

// 5. Consent page + Allow
r = await fetch(connectUrl, { headers: { cookie } });
const html = await r.text();
ok(html.includes("Connect Claude") && html.includes("Read your notes"), "consent page shows client + scopes");
const csrf = /name="csrf" value="([^"]+)"/.exec(html)[1];
const requestId = connectUrl.searchParams.get("requestId");
r = await fetch(`${base}/oauth/consent`, { method: "POST", redirect: "manual", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ requestId, csrf: "wrong".padEnd(csrf.length, "x"), decision: "allow" }) });
ok(r.status === 403, "bad CSRF rejected");
r = await fetch(`${base}/oauth/consent`, { method: "POST", redirect: "manual", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ requestId, csrf, decision: "allow" }) });
const back = new URL(r.headers.get("location"));
ok(back.origin + back.pathname === redirectUri && back.searchParams.get("state") === "xyz", "redirect to Claude with code + state");

// 6. Token exchange
const tokenBody = (extra) => new URLSearchParams({ client_id: client.client_id, ...extra });
r = await fetch(asm.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: tokenBody({ grant_type: "authorization_code", code: back.searchParams.get("code"), code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-123", redirect_uri: redirectUri, resource: `${base}/mcp` }) });
ok(r.status === 400, "wrong PKCE verifier rejected");
r = await fetch(asm.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: tokenBody({ grant_type: "authorization_code", code: back.searchParams.get("code"), code_verifier: verifier, redirect_uri: redirectUri, resource: `${base}/mcp` }) });
const tokens = await r.json();
ok(r.status === 200 && tokens.access_token && tokens.refresh_token, "tokens issued");

// 7. MCP calls
const mcp = async (token, method, params, id = 1) => {
  const res = await fetch(`${base}/mcp`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
  const text = await res.text();
  const data = text.split("\n").find((l) => l.startsWith("data: "));
  return { status: res.status, body: data ? JSON.parse(data.slice(6)) : text };
};
let m = await mcp(tokens.access_token, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "1" } });
ok(m.status === 200 && m.body.result.serverInfo.name === "agenthuman-ux", "initialize");
const icon = m.body.result.serverInfo.icons?.[0];
ok(m.body.result.serverInfo.title && icon?.src.endsWith("/favicon.svg"), "serverInfo carries brand title + icon");
m = await mcp(tokens.access_token, "tools/list", {});
ok(m.body.result.tools.map((t) => t.name).sort().join(",") === "create_note,delete_note,get_activity,list_notes,whoami", "tools/list");
m = await mcp(tokens.access_token, "tools/call", { name: "create_note", arguments: { title: "Hello", body: "from e2e" } });
ok(!m.body.result.isError && m.body.result.structuredContent.note.id, "create_note");
m = await mcp(tokens.access_token, "tools/call", { name: "list_notes", arguments: {} });
ok(m.body.result.structuredContent.notes[0].title === "Hello", "list_notes returns it");
m = await mcp(tokens.access_token, "tools/call", { name: "whoami", arguments: {} });
ok(m.body.result.structuredContent.email === "test@example.com", "whoami");

// 8. Refresh rotation + reuse detection
r = await fetch(asm.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: tokenBody({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }) });
const rotated = await r.json();
ok(r.status === 200 && rotated.access_token !== tokens.access_token, "refresh rotates tokens");
r = await fetch(asm.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: tokenBody({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }) });
ok(r.status === 400, "reused refresh token rejected");
m = await mcp(rotated.access_token, "tools/list", {});
ok(m.status === 401, "reuse killed the whole token family");

// 9. Branding
r = await fetch(`${base}/favicon.ico`);
ok(r.status === 200 && r.headers.get("content-type").startsWith("image/"), "favicon.ico served");
r = await fetch(icon.src);
ok(r.status === 200, "icon URL from serverInfo resolves");
ok(html.includes('rel="icon" href="/favicon.ico"'), "consent page links favicon");

// 10. Method guard
r = await fetch(`${base}/mcp`);
ok(r.status === 405, "GET /mcp → 405");
console.log("\nALL PASSED");
