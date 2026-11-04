/**
 * Bearer token storage: in memory, mirrored to sessionStorage so a reload in the same tab keeps
 * the session. Never localStorage (shared across tabs, survives the browser), never logged.
 */
const STORAGE_KEY = "veritas.session";

interface StoredSession {
  token: string;
  expiresAt: number;
}

let current: StoredSession | null = null;
const listeners = new Set<() => void>();

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

function notify(): void {
  for (const fn of listeners) fn();
}

function readStored(): StoredSession | null {
  const raw = storage()?.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<StoredSession>;
    if (typeof parsed.token === "string" && typeof parsed.expiresAt === "number") {
      return { token: parsed.token, expiresAt: parsed.expiresAt };
    }
  } catch {
    /* corrupt entry: fall through and drop it */
  }
  storage()?.removeItem(STORAGE_KEY);
  return null;
}

export function getToken(now: number = Date.now()): string | null {
  current ??= readStored();
  if (current && current.expiresAt <= now) {
    clearToken();
    return null;
  }
  return current?.token ?? null;
}

export function setToken(token: string, expiresInS: number, now: number = Date.now()): void {
  current = { token, expiresAt: now + expiresInS * 1000 };
  storage()?.setItem(STORAGE_KEY, JSON.stringify(current));
  notify();
}

export function clearToken(): void {
  const had = current !== null || storage()?.getItem(STORAGE_KEY) != null;
  current = null;
  storage()?.removeItem(STORAGE_KEY);
  if (had) notify();
}

export function subscribeToken(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** Test hook: forget the in-memory copy so the next read goes to sessionStorage. */
export function resetTokenMemory(): void {
  current = null;
}

export const TOKEN_STORAGE_KEY = STORAGE_KEY;
