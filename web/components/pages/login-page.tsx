"use client";

import { useMutation } from "@tanstack/react-query";
import { FileSignatureIcon, KeyRoundIcon, LinkIcon, UsersRoundIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { BrandMark } from "@/components/brand";
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

const FEATURES = [
  {
    icon: LinkIcon,
    title: "Hash-chained custody",
    text: "Every acquisition, access and export is Ed25519-signed into a verifiable ledger.",
  },
  {
    icon: UsersRoundIcon,
    title: "Four-eyes review",
    text: "Rules propose, an examiner confirms and an independent reviewer approves.",
  },
  {
    icon: FileSignatureIcon,
    title: "Signed reporting",
    text: "Reports carry their SHA-256 and signature, verifiable offline.",
  },
];

/** Decorative ledger illustration: signed blocks linked by their hashes. */
function LedgerIllustration() {
  const blocks = [
    { x: 24, y: 40, h: "13cf…af0f", k: "genesis" },
    { x: 150, y: 96, h: "be13…eee4", k: "ingest" },
    { x: 276, y: 52, h: "51dc…8ed1", k: "access" },
    { x: 402, y: 108, h: "d0cd…e026", k: "anchor" },
  ];
  return (
    <svg viewBox="0 0 520 190" className="w-full max-w-lg" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="login-link" x1="0" x2="1">
          <stop offset="0" stopColor="#7aa7ff" />
          <stop offset="1" stopColor="#5ee0d0" />
        </linearGradient>
      </defs>
      {blocks.slice(1).map((b, i) => {
        const a = blocks[i];
        if (!a) return null;
        return (
          <path
            key={b.h}
            d={`M${a.x + 100},${a.y + 22} C${a.x + 128},${a.y + 22} ${b.x - 28},${b.y + 22} ${b.x},${b.y + 22}`}
            fill="none"
            stroke="url(#login-link)"
            strokeWidth="2"
            strokeDasharray="4 4"
            opacity="0.85"
          />
        );
      })}
      {blocks.map((b) => (
        <g key={b.h} transform={`translate(${b.x} ${b.y})`}>
          <rect
            width="100"
            height="44"
            rx="9"
            fill="#ffffff"
            fillOpacity="0.07"
            stroke="#ffffff"
            strokeOpacity="0.22"
          />
          <circle cx="16" cy="22" r="6" fill="url(#login-link)" />
          <text
            x="30"
            y="19"
            fill="#e6ecff"
            fontSize="10"
            fontFamily="ui-sans-serif, system-ui"
            fontWeight="600"
          >
            {b.k}
          </text>
          <text x="30" y="32" fill="#b9c4e6" fontSize="9" fontFamily="ui-monospace, monospace">
            {b.h}
          </text>
        </g>
      ))}
    </svg>
  );
}

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
    <div className="grid min-h-dvh lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      <aside
        aria-label="About Veritas"
        className="relative hidden flex-col justify-between overflow-hidden bg-[#0f1630] p-10 text-white lg:flex"
      >
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0"
          style={{
            backgroundImage:
              "radial-gradient(60rem 30rem at 0% 0%, rgb(79 110 247 / 0.35), transparent 60%), radial-gradient(40rem 26rem at 100% 100%, rgb(45 212 191 / 0.22), transparent 60%), radial-gradient(circle at 1px 1px, rgb(255 255 255 / 0.07) 1px, transparent 0)",
            backgroundSize: "auto, auto, 22px 22px",
          }}
        />
        <div className="relative flex items-center gap-2.5 text-lg font-semibold tracking-tight">
          <BrandMark className="size-8" />
          Veritas <span className="font-normal text-[#c3cdf0]">DFIR</span>
        </div>
        <div className="relative grid max-w-xl gap-8">
          <div className="grid gap-3">
            <p className="text-3xl leading-tight font-semibold tracking-tight xl:text-4xl">
              Forensic findings you can defend in court.
            </p>
            <p className="text-base text-[#c3cdf0]">
              One examiner workspace for evidence intake, super-timelines, analytics and signed reporting,
              with integrity checks at every step.
            </p>
          </div>
          <LedgerIllustration />
          <ul className="grid gap-4">
            {FEATURES.map((f) => (
              <li key={f.title} className="flex gap-3">
                <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-white/15 bg-white/10">
                  <f.icon className="size-4.5" aria-hidden />
                </span>
                <span>
                  <span className="block text-sm font-semibold">{f.title}</span>
                  <span className="block text-sm text-[#c3cdf0]">{f.text}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-xs text-[#a9b5dd]">
          Authorised examiners only. Sessions are recorded in a tamper-evident audit log.
        </p>
      </aside>
      <div className="flex min-h-dvh flex-col">
        <header className="flex items-center justify-between px-4 py-3 lg:justify-end">
          <span className="flex items-center gap-2 font-semibold tracking-tight lg:hidden">
            <BrandMark />
            Veritas DFIR
          </span>
          <ThemeToggle />
        </header>
        <main
          id="main"
          className="flex flex-1 items-start justify-center px-4 pt-[8vh] pb-16 lg:items-center lg:pt-0"
        >
          <div className="bg-card w-full max-w-sm rounded-xl border p-7 shadow-sm">
            <h1 className="text-xl font-semibold tracking-tight">Sign in</h1>
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
    </div>
  );
}
