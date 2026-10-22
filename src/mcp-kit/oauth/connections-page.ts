import { escapeHtml, page } from "../html.js";
import type { Branding } from "../types.js";

export type ConnectionRow = {
  id: string;
  clientName: string;
  scopes: string[];
  createdAt: Date;
  expiresAt: Date;
};

const day = (date: Date) => date.toISOString().slice(0, 10);

/** "Connected apps": every AI app the user allowed, with a Disconnect button each. */
export function renderConnectionsPage(input: {
  branding: Branding;
  connections: ConnectionRow[];
  scopeLabels: Readonly<Record<string, string>>;
  csrf: string;
}) {
  const rows = input.connections
    .map(
      (connection) => `
      <li class="connection">
        <div>
          <strong>${escapeHtml(connection.clientName)}</strong>
          <p>${connection.scopes.map((scope) => escapeHtml(input.scopeLabels[scope] ?? scope)).join(" · ")}</p>
          <p>Connected ${day(connection.createdAt)} · ends ${day(connection.expiresAt)}</p>
        </div>
        <form method="post" action="/connections/disconnect">
          <input type="hidden" name="connectionId" value="${escapeHtml(connection.id)}">
          <input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
          <button class="secondary" type="submit">Disconnect</button>
        </form>
      </li>`
    )
    .join("");
  return page(
    input.branding,
    "Connected apps",
    `<h1>Connected apps</h1>
     <p>AI apps that can use your ${escapeHtml(input.branding.name)} account. Disconnecting stops them immediately.</p>
     ${rows ? `<ul class="connections">${rows}</ul>` : `<p>No apps are connected.</p>`}`
  );
}
