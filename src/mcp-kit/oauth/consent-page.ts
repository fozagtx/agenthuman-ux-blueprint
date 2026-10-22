import { escapeHtml, page } from "../html.js";
import type { Branding } from "../types.js";
import type { PendingAuthorization } from "./provider.js";

/**
 * The screen the user sees when an AI app asks to connect. Restyle freely, or
 * render it in your own frontend and POST the same fields to /oauth/consent.
 */
export function renderConsentPage(input: {
  pending: PendingAuthorization;
  branding: Branding;
  scopeLabels: Readonly<Record<string, string>>;
  csrf: string;
}) {
  const client = escapeHtml(input.pending.clientName);
  const scopes = input.pending.scopes
    .map((scope) => `<li>${escapeHtml(input.scopeLabels[scope] ?? scope)}</li>`)
    .join("");
  const hidden = `
    <input type="hidden" name="requestId" value="${escapeHtml(input.pending.requestId)}">
    <input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">`;
  const button = (decision: "allow" | "deny", label: string, className = "") => `
    <form method="post" action="/oauth/consent" style="flex:1;display:flex">
      ${hidden}<input type="hidden" name="decision" value="${decision}">
      <button class="${className}" type="submit">${label}</button>
    </form>`;
  // The name is chosen by the client; the hosts are what can't be faked.
  const origin = input.pending.verifiedClientHost
    ? `Verified app from <strong>${escapeHtml(input.pending.verifiedClientHost)}</strong>.`
    : `This app named itself; it isn't verified.`;
  return page(
    input.branding,
    `Connect ${input.pending.clientName}`,
    `<h1>Connect ${client}</h1>
     <p>${client} wants to use your ${escapeHtml(input.branding.name)} account. It will be able to:</p>
     <ul>${scopes}</ul>
     <p class="note">${origin} After you allow, you'll be sent to
       <strong>${escapeHtml(input.pending.redirectHost)}</strong>. Only continue if that's the AI app you're using.</p>
     <div class="row">${button("deny", "Cancel", "secondary")}${button("allow", "Allow")}</div>`
  );
}

export function renderExpiredPage(branding: Branding) {
  return page(
    branding,
    "Link expired",
    `<h1>This link has expired</h1><p>Start the connection again from your AI app.</p>`
  );
}
