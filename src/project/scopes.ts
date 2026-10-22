/**
 * What a connected AI client can ask to do. Each tool requires one of these,
 * and the consent page lists the labels so the user sees what they allow.
 * Rename for your project, e.g. "orders:read": "See your orders".
 */
export const SCOPES = {
  "notes:read": "Read your notes",
  "notes:write": "Create and delete notes",
} as const;

export type Scope = keyof typeof SCOPES;
