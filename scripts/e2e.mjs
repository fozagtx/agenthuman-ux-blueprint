// End-to-end check of what web AI chat clients do against this server:
// discover → register (DCR) or identify by URL (CIMD) → authorize → consent → token → /mcp.
// Needs the server running with DEV_LOGIN=true (dev login + loopback CIMD).
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";

const base = process.env.BASE_URL ?? "http://localhost:4000";
const ok = (cond, label) => { if (!cond) throw new Error(`FAIL: ${label}`); console.log(`ok  ${label}`); };
const form = (body) => ({ method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(body) });
const pkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

// ── Discovery ────────────────────────────────────────────────────────────────
let r = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
ok(r.status === 401 && /resource_metadata=/.test(r.headers.get("www-authenticate") ?? ""), "401 + WWW-Authenticate resource_metadata");
const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
ok(prm.resource === `${base}/mcp`, "protected resource metadata (RFC 9728 path)");
const rootPrm = await (await fetch(`${base}/.well-known/oauth-protected-resource`)).json();
ok(rootPrm.resource === prm.resource && rootPrm.authorization_servers[0] === prm.authorization_servers[0], "protected resource metadata (root path)");
const asm = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
ok(asm.code_challenge_methods_supported.includes("S256") && asm.registration_endpoint, "AS metadata: PKCE S256 + DCR");
ok(asm.client_id_metadata_document_supported === true && asm.token_endpoint_auth_methods_supported.includes("none"), "AS metadata: CIMD + public clients (ChatGPT, Claude)");
ok(asm.authorization_response_iss_parameter_supported === true && prm.authorization_servers[0] === asm.issuer, "AS metadata: RFC 9207 iss, issuer matches PRM");

// ── Sign in once (dev login) ─────────────────────────────────────────────────
r = await fetch(`${base}/login`, form({ email: "test@example.com", next: "/" }));
const cookie = r.headers.get("set-cookie").split(";")[0];
ok(r.status === 303 && cookie.startsWith("mcp_session="), "dev login sets session cookie");

/** Runs /authorize → /connect → Allow. Returns the redirect back to the client. */
async function authorize({ clientId, redirectUri, scope = "notes:read notes:write", resource = `${base}/mcp`, decision = "allow" }) {
  const { verifier, challenge } = pkce();
  const url = new URL(asm.authorization_endpoint);
  const params = { response_type: "code", client_id: clientId, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256", state: "xyz", scope };
  if (resource) params.resource = resource;
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  const res = await fetch(url, { redirect: "manual" });
  const location = new URL(res.headers.get("location") ?? "", base);
  if (location.pathname !== "/connect") return { status: res.status, location, verifier };
  const page = await fetch(location, { headers: { cookie } });
  const html = await page.text();
  const csrf = /name="csrf" value="([^"]+)"/.exec(html)[1];
  const consent = await fetch(`${base}/oauth/consent`, { ...form({ requestId: location.searchParams.get("requestId"), csrf, decision }), headers: { cookie, "content-type": "application/x-www-form-urlencoded" } });
  return { status: consent.status, location: new URL(consent.headers.get("location")), verifier, html, page, connectUrl: location, csrf };
}

const token = (body) => fetch(asm.token_endpoint, form(body));

const mcp = async (accessToken, method, params, id = 1) => {
  const res = await fetch(`${base}/mcp`, { method: "POST", headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
  const text = await res.text();
  const data = text.split("\n").find((l) => l.startsWith("data: "));
  return { status: res.status, body: data ? JSON.parse(data.slice(6)) : text };
};

// ── DCR client (Le Chat style; Claude's fallback) ────────────────────────────
const claudeRedirect = "https://claude.ai/api/mcp/auth_callback";
r = await fetch(asm.registration_endpoint, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ client_name: "Claude", redirect_uris: [claudeRedirect], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }),
});
const dcr = await r.json();
ok(r.status === 201 && dcr.client_id, "DCR: client registered");

let a = await authorize({ clientId: dcr.client_id, redirectUri: claudeRedirect });
ok(a.html.includes("Connect Claude") && a.html.includes("Read your notes"), "consent page shows client + scopes");
ok(a.html.includes("isn't verified") && a.html.includes("claude.ai"), "consent page: DCR name marked unverified, shows redirect host");
ok(a.page.headers.get("x-frame-options") === "DENY" && /frame-ancestors 'none'/.test(a.page.headers.get("content-security-policy")), "consent page refuses framing");
ok(a.html.includes('rel="icon" href="/favicon.ico"'), "consent page links favicon");
const bad = await fetch(`${base}/oauth/consent`, { ...form({ requestId: a.connectUrl.searchParams.get("requestId"), csrf: "x".repeat(a.csrf.length), decision: "allow" }), headers: { cookie, "content-type": "application/x-www-form-urlencoded" } });
ok(bad.status === 403 || bad.status === 400, "bad CSRF rejected");
ok(a.location.origin + a.location.pathname === claudeRedirect && a.location.searchParams.get("state") === "xyz", "redirect back with code + state");
ok(a.location.searchParams.get("iss") === asm.issuer, "redirect carries iss (RFC 9207)");

r = await token({ client_id: dcr.client_id, grant_type: "authorization_code", code: a.location.searchParams.get("code"), code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-123", redirect_uri: claudeRedirect, resource: `${base}/mcp` });
ok(r.status === 400, "wrong PKCE verifier rejected");
r = await token({ client_id: dcr.client_id, grant_type: "authorization_code", code: a.location.searchParams.get("code"), code_verifier: a.verifier, redirect_uri: claudeRedirect, resource: `${base}/mcp` });
const tokens = await r.json();
ok(r.status === 200 && tokens.access_token && tokens.refresh_token, "tokens issued");

let m = await mcp(tokens.access_token, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "1" } });
ok(m.status === 200 && m.body.result.serverInfo.name === "agenthuman-ux", "initialize");
const icon = m.body.result.serverInfo.icons?.[0];
ok(m.body.result.serverInfo.title && icon?.src.endsWith("/favicon.svg"), "serverInfo carries brand title + icon");
m = await mcp(tokens.access_token, "tools/list", {});
const tools = m.body.result.tools;
ok(tools.map((t) => t.name).sort().join(",") === "create_note,delete_note,get_activity,list_notes,whoami", "tools/list");
const whoamiTool = tools.find((t) => t.name === "whoami");
ok(whoamiTool._meta?.["openai/profile"] === true && whoamiTool.outputSchema?.additionalProperties === false, "whoami is a ChatGPT profile tool");
m = await mcp(tokens.access_token, "tools/call", { name: "create_note", arguments: { title: "Hello", body: "from e2e" } });
ok(!m.body.result.isError && m.body.result.structuredContent.note.id, "create_note");
m = await mcp(tokens.access_token, "tools/call", { name: "list_notes", arguments: {} });
ok(m.body.result.structuredContent.notes[0].title === "Hello", "list_notes returns it");
m = await mcp(tokens.access_token, "tools/call", { name: "whoami", arguments: {} });
const profile = m.body.result.structuredContent;
ok(profile.id && profile.email === "test@example.com" && Object.keys(profile).every((k) => ["id", "email"].includes(k)), "whoami returns stable id + email only");

r = await token({ client_id: dcr.client_id, grant_type: "refresh_token", refresh_token: tokens.refresh_token });
const rotated = await r.json();
ok(r.status === 200 && rotated.access_token !== tokens.access_token, "refresh rotates tokens");
m = await mcp(tokens.access_token, "tools/list", {});
ok(m.status === 200, "old access token keeps working until it expires");
r = await token({ client_id: "someone-else", grant_type: "refresh_token", refresh_token: rotated.refresh_token });
ok(r.status === 400 || r.status === 401, "refresh token can't be used by another client");
r = await token({ client_id: dcr.client_id, grant_type: "refresh_token", refresh_token: tokens.refresh_token });
ok(r.status === 400, "reused refresh token rejected");
m = await mcp(rotated.access_token, "tools/list", {});
ok(m.status === 401, "refresh reuse revokes the whole grant (thief and victim both cut off)");
r = await token({ client_id: dcr.client_id, grant_type: "refresh_token", refresh_token: rotated.refresh_token });
ok(r.status === 400, "…including the newest refresh token");

/** Fresh tokens for the DCR client. */
async function connect() {
  const res = await authorize({ clientId: dcr.client_id, redirectUri: claudeRedirect });
  const code = res.location.searchParams.get("code");
  const issued = await (await token({ client_id: dcr.client_id, grant_type: "authorization_code", code, code_verifier: res.verifier, redirect_uri: claudeRedirect })).json();
  return { ...issued, code, verifier: res.verifier };
}

let fresh = await connect();
r = await token({ client_id: dcr.client_id, grant_type: "authorization_code", code: fresh.code, code_verifier: fresh.verifier, redirect_uri: claudeRedirect });
ok(r.status === 400, "authorization code is single-use");
ok((await mcp(fresh.access_token, "tools/list", {})).status === 401, "replaying a code revokes the tokens it issued");

fresh = await connect();
r = await fetch(asm.revocation_endpoint, form({ client_id: "another-client", token: fresh.refresh_token }));
ok((await mcp(fresh.access_token, "tools/list", {})).status === 200, "another client can't revoke your tokens");
r = await fetch(asm.revocation_endpoint, form({ client_id: dcr.client_id, token: fresh.refresh_token }));
ok(r.status === 200 && (await mcp(fresh.access_token, "tools/list", {})).status === 401, "revoking a refresh token ends the grant");

fresh = await connect();
let page = await (await fetch(`${base}/connections`, { headers: { cookie } })).text();
const connectionIds = [...page.matchAll(/name="connectionId" value="([^"]+)"/g)].map((match) => match[1]);
const listCsrf = /name="csrf" value="([^"]+)"/.exec(page)[1];
ok(page.includes("Connected apps") && connectionIds.length >= 1, "connections page lists connected apps");
r = await fetch(`${base}/connections/disconnect`, { ...form({ connectionId: connectionIds.at(-1), csrf: "x".repeat(listCsrf.length) }), headers: { cookie, "content-type": "application/x-www-form-urlencoded" } });
ok(r.status === 403, "disconnect requires the CSRF token");
for (const connectionId of connectionIds) {
  await fetch(`${base}/connections/disconnect`, { ...form({ connectionId, csrf: listCsrf }), headers: { cookie, "content-type": "application/x-www-form-urlencoded" } });
}
ok((await mcp(fresh.access_token, "tools/list", {})).status === 401, "Disconnect revokes access immediately");

r = await fetch(`${base}/login`, form({ email: "x@example.com", next: "/\\evil.example" }));
ok(r.headers.get("location") === "/", "login `next` can't redirect off-site (/\\evil)");

// ── Edge cases every client can hit ──────────────────────────────────────────
a = await authorize({ clientId: dcr.client_id, redirectUri: claudeRedirect, resource: null });
r = await token({ client_id: dcr.client_id, grant_type: "authorization_code", code: a.location.searchParams.get("code"), code_verifier: a.verifier, redirect_uri: claudeRedirect });
const noResource = await r.json();
m = await mcp(noResource.access_token, "tools/list", {});
ok(m.status === 200, "client that omits `resource` still gets a working token");

a = await authorize({ clientId: dcr.client_id, redirectUri: claudeRedirect, resource: "https://evil.example/mcp" });
ok(a.status === 400, "foreign `resource` rejected; unverified client gets an error page, not a redirect");

a = await authorize({ clientId: dcr.client_id, redirectUri: claudeRedirect, scope: "admin:everything" });
ok(a.status === 400, "only-unknown scopes rejected (no open redirect for unverified clients)");

a = await authorize({ clientId: dcr.client_id, redirectUri: claudeRedirect, decision: "deny" });
ok(a.location.searchParams.get("error") === "access_denied" && a.location.searchParams.get("iss") === asm.issuer, "Cancel → access_denied with iss");

r = await fetch(new URL(`${asm.authorization_endpoint}?response_type=code&client_id=${dcr.client_id}&redirect_uri=${encodeURIComponent("https://evil.example/cb")}&code_challenge=x&code_challenge_method=S256`), { redirect: "manual" });
ok(r.status === 400, "unregistered redirect_uri rejected without redirecting");

// ── CIMD client (ChatGPT / Claude style): client_id is a metadata URL ───────
const chatgptRedirect = "https://chatgpt.com/connector_platform_oauth_redirect";
const documents = {};
const metadataServer = createServer((req, res) => {
  const doc = documents[req.url];
  res.writeHead(doc ? 200 : 404, { "content-type": "application/json" }).end(doc ? JSON.stringify(doc) : "{}");
});
await new Promise((resolve) => metadataServer.listen(4100, "127.0.0.1", resolve));
const cimdId = "http://localhost:4100/oauth/client.json";
documents["/oauth/client.json"] = {
  client_id: cimdId, client_name: "ChatGPT", redirect_uris: [chatgptRedirect],
  grant_types: ["authorization_code", "refresh_token"], response_types: ["code"],
  token_endpoint_auth_methods_supported: ["none", "private_key_jwt"], token_endpoint_auth_method: "private_key_jwt",
};
documents["/oauth/mismatch.json"] = { ...documents["/oauth/client.json"], client_id: "http://localhost:4100/oauth/other.json" };
documents["/oauth/secret-only.json"] = { ...documents["/oauth/client.json"], client_id: "http://localhost:4100/oauth/secret-only.json", token_endpoint_auth_methods_supported: ["client_secret_basic"], token_endpoint_auth_method: "client_secret_basic" };

try {
  a = await authorize({ clientId: cimdId, redirectUri: chatgptRedirect });
  ok(a.html.includes("Connect ChatGPT") && a.html.includes("Verified app from <strong>localhost:4100"), "CIMD: document fetched, consent shows verified host");
  ok(a.location.origin + a.location.pathname === chatgptRedirect && a.location.searchParams.get("iss") === asm.issuer, "CIMD: redirect to ChatGPT's stable callback with iss");
  r = await token({ client_id: cimdId, grant_type: "authorization_code", code: a.location.searchParams.get("code"), code_verifier: a.verifier, redirect_uri: chatgptRedirect, resource: `${base}/mcp` });
  const cimdTokens = await r.json();
  ok(r.status === 200 && cimdTokens.access_token, "CIMD: public-client token exchange (no secret)");
  a = await authorize({ clientId: cimdId, redirectUri: chatgptRedirect, scope: "admin:everything" });
  ok(a.location.searchParams.get("error") === "invalid_scope" && a.location.searchParams.get("iss") === asm.issuer, "CIMD: errors redirect back to the verified client, with iss");
  m = await mcp(cimdTokens.access_token, "tools/call", { name: "whoami", arguments: {} });
  ok(m.body.result.structuredContent.id === profile.id, "CIMD: same user, same profile id across clients");

  r = await fetch(`${asm.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent("http://localhost:4100/oauth/mismatch.json")}&redirect_uri=${encodeURIComponent(chatgptRedirect)}&code_challenge=x&code_challenge_method=S256`, { redirect: "manual" });
  ok(r.status === 400, "CIMD: document whose client_id doesn't match its URL is rejected");
  r = await fetch(`${asm.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent("http://localhost:4100/oauth/secret-only.json")}&redirect_uri=${encodeURIComponent(chatgptRedirect)}&code_challenge=x&code_challenge_method=S256`, { redirect: "manual" });
  ok(r.status === 400, "CIMD: client that can't be a public client is rejected");
  r = await fetch(`${asm.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(cimdId)}&redirect_uri=${encodeURIComponent("https://evil.example/cb")}&code_challenge=x&code_challenge_method=S256`, { redirect: "manual" });
  ok(r.status === 400, "CIMD: redirect_uri outside the document rejected");
  r = await fetch(`${asm.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent("https://127.0.0.1/oauth/client.json")}&redirect_uri=${encodeURIComponent(chatgptRedirect)}&code_challenge=x&code_challenge_method=S256`, { redirect: "manual" });
  ok(r.status === 400, "CIMD: private-address metadata URL refused (SSRF)");
  for (const host of ["[::ffff:127.0.0.1]", "[::ffff:a9fe:a9fe]", "[64:ff9b::7f00:1]", "[2002:7f00:1::]"]) {
    r = await fetch(`${asm.authorization_endpoint}?response_type=code&client_id=${encodeURIComponent(`https://${host}/oauth/client.json`)}&redirect_uri=${encodeURIComponent(chatgptRedirect)}&code_challenge=x&code_challenge_method=S256`, { redirect: "manual" });
    const body = await r.text();
    ok(r.status === 400 && body.includes("Could not fetch client metadata") && !/ECONN|HTTP \d|JSON/.test(body), `CIMD: ${host} refused with a generic error`);
  }
} finally {
  metadataServer.close();
}

// ── Branding + transport ────────────────────────────────────────────────────
r = await fetch(`${base}/favicon.ico`);
ok(r.status === 200 && r.headers.get("content-type").startsWith("image/") && /default-src 'none'/.test(r.headers.get("content-security-policy")), "favicon served with script-blocking CSP");
ok((await fetch(icon.src)).status === 200, "icon URL from serverInfo resolves");
ok((await fetch(`${base}/mcp`)).status === 405, "GET /mcp → 405");
console.log("\nALL PASSED");
