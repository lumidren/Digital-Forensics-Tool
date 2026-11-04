"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Alert } from "@/components/ui/misc";
import { oidcConfig } from "@/lib/config";
import { completeLogin } from "@/lib/oidc";
import { setToken } from "@/lib/token-store";

export function OidcCallback() {
  const params = useSearchParams();
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const cfg = oidcConfig();
    if (!cfg) {
      setError("Single sign-on is not configured for this deployment.");
      return;
    }
    completeLogin(cfg, new URLSearchParams(params.toString()), `${window.location.origin}/auth/callback`, {
      fetchImpl: fetch.bind(window),
      crypto: window.crypto,
      storage: window.sessionStorage,
    })
      .then(({ token, expiresIn, next }) => {
        setToken(token, expiresIn);
        router.replace(next);
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Sign-in failed."));
  }, [params, router]);

  return (
    <main id="main" className="mx-auto mt-[15vh] max-w-sm px-4">
      <h1 className="text-lg font-semibold">Single sign-on</h1>
      {error ? (
        <div className="mt-3 grid gap-3">
          <Alert variant="destructive" role="alert">
            {error}
          </Alert>
          <Link href="/login" className="text-primary text-sm underline">
            Back to sign in
          </Link>
        </div>
      ) : (
        <p role="status" className="text-muted-foreground mt-3 text-sm">
          Completing sign-in…
        </p>
      )}
    </main>
  );
}
