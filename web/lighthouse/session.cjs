/**
 * LHCI puppeteer script: signs in once through the API and makes every tab Lighthouse opens start
 * with that session in sessionStorage (the app never keeps tokens in cookies or localStorage).
 * The login page itself is audited signed out.
 * Credentials and the API URL come from the E2E stack state written by `npm run lhci`.
 */
const { readFileSync } = require("node:fs");
const { join } = require("node:path");

const STORAGE_KEY = "veritas.session";
let session = null;

async function getSession() {
  if (session) return session;
  const state = JSON.parse(readFileSync(join(process.cwd(), "e2e", ".state", "stack.json"), "utf8"));
  const res = await fetch(`${state.apiUrl}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: state.users.alice.username, password: state.users.alice.password }),
  });
  if (!res.ok) throw new Error(`login failed: ${res.status}`);
  const body = await res.json();
  session = JSON.stringify({ token: body.access_token, expiresAt: Date.now() + body.expires_in * 1000 });
  return session;
}

module.exports = async (browser) => {
  const value = await getSession();
  if (browser.__veritasSession) return;
  browser.__veritasSession = true;
  const inject = async (target) => {
    if (target.type() !== "page") return;
    const page = await target.page();
    if (!page) return;
    await page.evaluateOnNewDocument(
      (key, v) => {
        try {
          // The login page is measured signed out; every other page signed in.
          if (window.location.pathname.startsWith("/login")) window.sessionStorage.removeItem(key);
          else window.sessionStorage.setItem(key, v);
        } catch {
          /* opaque origins (about:blank) have no storage */
        }
      },
      STORAGE_KEY,
      value,
    );
  };
  browser.on("targetcreated", (t) => {
    void inject(t);
  });
  await Promise.all(browser.targets().map(inject));
};
