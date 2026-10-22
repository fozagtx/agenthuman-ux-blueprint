import type { Branding } from "./types.js";

export function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Hex colours only, so a misconfigured value can never inject CSS. */
function safeColor(value: string | undefined, fallback: string) {
  return value && /^#[0-9a-f]{3,8}$/i.test(value) ? value : fallback;
}

/**
 * Minimal branded page shell: favicon, name and accent colour come from
 * Branding. Restyle freely, or render these steps in your own frontend.
 */
export function page(branding: Branding, title: string, body: string) {
  const accent = safeColor(branding.accentColor, "#4054d6");
  const name = escapeHtml(branding.name);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} · ${name}</title>
<link rel="icon" href="/favicon.ico">
<style>
  :root { color-scheme: light dark; --bg:#f6f4ef; --card:#fff; --ink:#151515; --muted:#666; --line:#e4e0d8; --accent:${accent}; }
  @media (prefers-color-scheme: dark) { :root { --bg:#121212; --card:#1c1c1c; --ink:#f2f2f2; --muted:#a0a0a0; --line:#2e2e2e; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center; padding:16px;
         background:var(--bg); color:var(--ink); font:15px/1.5 system-ui, sans-serif; }
  .card { width:100%; max-width:460px; background:var(--card); border:1px solid var(--line);
          border-radius:20px; padding:28px; }
  .brand { display:flex; align-items:center; gap:10px; margin:0 0 20px; font-weight:600; }
  .brand img { width:28px; height:28px; border-radius:7px; }
  h1 { margin:0 0 8px; font-size:24px; letter-spacing:-0.02em; }
  p { margin:0 0 16px; color:var(--muted); }
  ul { margin:0 0 20px; padding-left:20px; }
  li { margin:4px 0; }
  input { width:100%; padding:10px 12px; margin:0 0 12px; border:1px solid var(--line);
          border-radius:10px; background:transparent; color:inherit; font:inherit; }
  .row { display:flex; gap:10px; }
  button { flex:1; padding:11px 14px; border-radius:10px; border:1px solid var(--accent);
           font:inherit; font-weight:600; cursor:pointer; background:var(--accent); color:#fff; }
  button.secondary { background:transparent; color:var(--ink); border-color:var(--line); }
</style>
</head>
<body><main class="card">
<div class="brand"><img src="/favicon.ico" alt="">${name}</div>
${body}
</main></body>
</html>`;
}
