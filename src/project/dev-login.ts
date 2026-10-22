import express, { Router } from "express";
import type { Database } from "../db/client.js";
import { escapeHtml, page, sendPage, type Branding, type Session } from "../mcp-kit/index.js";
import { users } from "./schema.js";
import { safeNext } from "./session.js";

/**
 * Email-only sign-in so the blueprint runs end to end on its own.
 * It proves nothing about who the person is. Only mounted when DEV_LOGIN=true;
 * delete this file once your real login is wired into session.ts.
 */
export function createDevLoginRouter(db: Database, session: Session, branding: Branding) {
  const router = Router();

  router.get("/login", (request, response) => {
    const next = escapeHtml(safeNext(request.query.next));
    sendPage(
      response,
      page(
        branding,
        "Sign in",
        `<h1>Sign in</h1>
         <p>Development login. Replace with your real auth.</p>
         <form method="post" action="/login">
           <input type="hidden" name="next" value="${next}">
           <input type="email" name="email" placeholder="you@example.com" required autofocus>
           <div class="row"><button type="submit">Continue</button></div>
         </form>`
      )
    );
  });

  router.post("/login", express.urlencoded({ extended: false }), async (request, response, next) => {
    try {
      const email = String(request.body?.email ?? "").trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+$/.test(email)) {
        sendPage(response, page(branding, "Sign in", `<h1>Enter a valid email</h1>`), 400);
        return;
      }
      const [user] = await db
        .insert(users)
        .values({ email })
        .onConflictDoUpdate({ target: users.email, set: { email } })
        .returning({ id: users.id });
      session.start(response, user!.id);
      response.redirect(303, safeNext(request.body?.next));
    } catch (error) {
      next(error);
    }
  });

  return router;
}
