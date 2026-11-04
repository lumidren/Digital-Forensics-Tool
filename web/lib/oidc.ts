/**
 * OpenID Connect authorization-code flow with PKCE (RFC 7636) for a public browser client.
 * The verifier and state live in sessionStorage only for the duration of the redirect.
 */
import type { OidcConfig } from "./config";

const PENDING_KEY = "veritas.oidc.pending";

export interface OidcDeps {
  fetchImpl: typeof fetch;
  crypto: Crypto;
  storage: Storage;
}

export interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
}

interface Pending {
  verifier: string;
  state: string;
  nonce: string;
  next: string;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomString(c: Crypto, bytes = 32): string {
  const buf = new Uint8Array(bytes);
  c.getRandomValues(buf);
  return base64UrlEncode(buf);
}

export async function pkceChallenge(c: Crypto, verifier: string): Promise<string> {
  const digest = await c.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

export async function discover(issuer: string, fetchImpl: typeof fetch): Promise<Discovery> {
  const res = await fetchImpl(`${issuer}/.well-known/openid-configuration`, {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) throw new Error(`OIDC discovery failed (${res.status})`);
  const d = (await res.json()) as Partial<Discovery>;
  if (!d.authorization_endpoint || !d.token_endpoint)
    throw new Error("OIDC discovery document is incomplete");
  return { authorization_endpoint: d.authorization_endpoint, token_endpoint: d.token_endpoint };
}

/** Build the authorization URL and remember verifier/state for the callback. */
export async function beginLogin(
  cfg: OidcConfig,
  redirectUri: string,
  next: string,
  deps: OidcDeps,
): Promise<string> {
  const disc = await discover(cfg.issuer, deps.fetchImpl);
  const pending: Pending = {
    verifier: randomString(deps.crypto, 48),
    state: randomString(deps.crypto, 16),
    nonce: randomString(deps.crypto, 16),
    next,
  };
  deps.storage.setItem(PENDING_KEY, JSON.stringify(pending));
  const url = new URL(disc.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", cfg.clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", cfg.scope);
  url.searchParams.set("state", pending.state);
  url.searchParams.set("nonce", pending.nonce);
  url.searchParams.set("code_challenge", await pkceChallenge(deps.crypto, pending.verifier));
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export interface OidcTokens {
  token: string;
  expiresIn: number;
  next: string;
}

/** Exchange the authorization code at the token endpoint. */
export async function completeLogin(
  cfg: OidcConfig,
  params: URLSearchParams,
  redirectUri: string,
  deps: OidcDeps,
): Promise<OidcTokens> {
  const raw = deps.storage.getItem(PENDING_KEY);
  deps.storage.removeItem(PENDING_KEY);
  if (params.get("error"))
    throw new Error(params.get("error_description") ?? params.get("error") ?? "login failed");
  if (!raw) throw new Error("No sign-in in progress; start again.");
  const pending = JSON.parse(raw) as Pending;
  const code = params.get("code");
  if (!code) throw new Error("Authorization code missing from the callback.");
  if (params.get("state") !== pending.state)
    throw new Error("State mismatch; the sign-in response was rejected.");
  const disc = await discover(cfg.issuer, deps.fetchImpl);
  const res = await deps.fetchImpl(disc.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: cfg.clientId,
      code_verifier: pending.verifier,
    }).toString(),
  });
  if (!res.ok) throw new Error(`Token exchange failed (${res.status})`);
  const body = (await res.json()) as { access_token?: string; id_token?: string; expires_in?: number };
  // The API verifies a JWT bearer; prefer a JWT access token, else the ID token.
  const token =
    body.access_token && body.access_token.split(".").length === 3 ? body.access_token : body.id_token;
  if (!token) throw new Error("The identity provider returned no usable token.");
  return { token, expiresIn: body.expires_in ?? 3600, next: safeNext(pending.next) };
}

/** Only allow same-origin relative paths as post-login destinations. */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return "/cases";
  return next;
}
