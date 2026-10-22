import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { Router } from "express";
import type { Branding } from "./types.js";

const MIME_TYPES: Record<string, string> = {
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

export function faviconMimeType(path: string) {
  const type = MIME_TYPES[extname(path).toLowerCase()];
  if (!type) throw new Error(`Favicon must be .svg, .png or .ico: ${path}`);
  return type;
}

/**
 * Serves the branded icon at /favicon.ico (what Claude and browsers look up
 * by default) and at /favicon.<ext> (what the MCP server's `icons` points to).
 * The file is read once at startup so a bad path fails fast.
 */
export function createFaviconRouter(branding: Branding) {
  const type = faviconMimeType(branding.faviconPath);
  const body = readFileSync(branding.faviconPath);
  const router = Router();
  const send = (_request: unknown, response: import("express").Response) => {
    response.set("Content-Type", type).set("Cache-Control", "public, max-age=86400").send(body);
  };
  router.get("/favicon.ico", send);
  router.get(`/favicon${extname(branding.faviconPath).toLowerCase()}`, send);
  return router;
}
