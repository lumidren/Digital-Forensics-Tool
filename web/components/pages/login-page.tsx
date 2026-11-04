"use client";

import { useMutation } from "@tanstack/react-query";
import { KeyRoundIcon, ShieldCheckIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert } from "@/components/ui/misc";
import { useHydrated, useToken } from "@/hooks/use-session";
import { ApiError } from "@/lib/api";
import { api } from "@/lib/api-instance";
import { oidcConfig } from "@/lib/config";
import { beginLogin, safeNext } from "@/lib/oidc";
import { setToken } from "@/lib/token-store";

export function LoginPage() {
  const router = useRouter();
  const nextPath = () => safeNext(new URLSearchParams(window.location.search).get("next"));
  const token = useToken();
  const hydrated = useHydrated();
  const oidc = oidcConfig();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [oidcError, setOidcError] = useState<string | null>(null);

  useEffect(() => {
    if (hydrated && token) router.replace(safeNext(new URLSearchParams(window.location.search).get("next")));
  }, [hydrated, token, router]);

  const login = useMutation({
    mutationFn: () => api.login(username.trim(), password),
    onSuccess: (res) => {
      setPassword("");
      setToken(res.access_token, res.expires_in);
      router.replace(nextPath());
    },
    meta: { silent: true },
  });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate();
  };

  const startOidc = async () => {
    if (!oidc) return;
    setOidcError(null);
    try {
      const url = await beginLogin(oidc, `${window.location.origin}/auth/callback`, nextPath(), {
        fetchImpl: fetch.bind(window),
        crypto: window.crypto,
        storage: window.sessionStorage,
      });
      window.location.assign(url);
    } catch (err) {
      setOidcError(err instanceof Error ? err.message : "Single sign-on is unavailable.");
    }
  };

  const error =
    login.error instanceof ApiError
      ? login.error.status === 401
        ? "Invalid username or password."
        : login.error.detail
      : login.error
        ? "The API could not be reached."
        : null;

  return (
    <div className="flex min-h-dvh flex-col">
      <header className="flex items-center justify-between px-4 py-3">
        <span className="flex items-center gap-1.5 font-semibold">
          <ShieldCheckIcon className="text-primary size-5" aria-hidden />
          Veritas DFIR
        </span>
        <ThemeToggle />
      </header>
      <main id="main" className="flex flex-1 items-start justify-center px-4 pt-[10vh]">
        <div className="bg-card w-full max-w-sm rounded-lg border p-6 shadow-xs">
          <h1 className="text-lg font-semibold">Sign in</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Examiner workspace. Every action is recorded in the audit log.
          </p>
          <form className="mt-5 grid gap-4" onSubmit={onSubmit} noValidate>
            <div className="grid gap-1.5">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                name="username"
                autoComplete="username"
                autoFocus
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-invalid={error ? true : undefined}
                aria-describedby={error ? "login-error" : undefined}
              />
            </div>
            <div aria-live="assertive">
              {error ? (
                <Alert id="login-error" variant="destructive" role="alert">
                  {error}
                </Alert>
              ) : null}
            </div>
            <Button type="submit" disabled={login.isPending || !username || !password}>
              {login.isPending ? "Signing in…" : "Sign in"}
            </Button>
          </form>
          {oidc ? (
            <div className="mt-4 grid gap-2 border-t pt-4">
              <Button variant="outline" onClick={() => void startOidc()}>
                <KeyRoundIcon aria-hidden /> Sign in with single sign-on
              </Button>
              {oidcError ? (
                <Alert variant="destructive" role="alert">
                  {oidcError}
                </Alert>
              ) : null}
            </div>
          ) : null}
        </div>
      </main>
    </div>
  );
}
