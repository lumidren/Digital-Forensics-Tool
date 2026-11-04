/** Build-time configuration. `NEXT_PUBLIC_*` values are inlined by Next.js at build time. */
export const API_URL: string = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(
  /\/+$/,
  "",
);

export interface OidcConfig {
  issuer: string;
  clientId: string;
  scope: string;
}

export function oidcConfig(
  env: Record<string, string | undefined> = {
    NEXT_PUBLIC_OIDC_ISSUER: process.env.NEXT_PUBLIC_OIDC_ISSUER,
    NEXT_PUBLIC_OIDC_CLIENT_ID: process.env.NEXT_PUBLIC_OIDC_CLIENT_ID,
    NEXT_PUBLIC_OIDC_SCOPE: process.env.NEXT_PUBLIC_OIDC_SCOPE,
  },
): OidcConfig | null {
  const issuer = env.NEXT_PUBLIC_OIDC_ISSUER?.trim();
  if (!issuer) return null;
  return {
    issuer: issuer.replace(/\/+$/, ""),
    clientId: env.NEXT_PUBLIC_OIDC_CLIENT_ID?.trim() || "veritas-web",
    scope: env.NEXT_PUBLIC_OIDC_SCOPE?.trim() || "openid profile email",
  };
}
