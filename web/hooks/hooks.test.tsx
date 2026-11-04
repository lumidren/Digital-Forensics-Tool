import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearToken, resetTokenMemory, setToken } from "@/lib/token-store";
import { useCase, useCaseId } from "./use-case";
import { useCaseSocket } from "./use-case-socket";
import { modalOpen, useHotkeys } from "./use-hotkeys";
import { useAccess, useHydrated, useMe, useToken } from "./use-session";
import { useTableNav } from "./use-table-nav";

vi.mock("next/navigation", () => ({ useParams: () => ({ caseId: "C-1%20x" }) }));

const press = (key: string, init: KeyboardEventInit = {}, target: EventTarget = window) => {
  const ev = new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true, ...init });
  act(() => {
    target.dispatchEvent(ev);
  });
  return ev;
};

describe("useHotkeys", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("fires single keys and sequences and prevents default", () => {
    const j = vi.fn();
    const gt = vi.fn();
    const palette = vi.fn();
    renderHook(() => useHotkeys({ j, "g t": gt, "mod+k": palette }, { scope: "global" }));
    expect(press("j").defaultPrevented).toBe(true);
    press("g");
    press("t");
    press("k", { ctrlKey: true });
    expect(j).toHaveBeenCalledOnce();
    expect(gt).toHaveBeenCalledOnce();
    expect(palette).toHaveBeenCalledOnce();
  });

  it("ignores keys typed into fields except mod+k and escape", () => {
    const j = vi.fn();
    const esc = vi.fn();
    const palette = vi.fn();
    renderHook(() => useHotkeys({ j, escape: esc, "mod+k": palette }));
    const input = document.createElement("input");
    document.body.appendChild(input);
    press("j", {}, input);
    press("Escape", {}, input);
    press("k", { metaKey: true }, input);
    expect(j).not.toHaveBeenCalled();
    expect(esc).toHaveBeenCalledOnce();
    expect(palette).toHaveBeenCalledOnce();
  });

  it("suspends page bindings while a modal is open and skips modifiers, handled and composing events", () => {
    const pageJ = vi.fn();
    const globalJ = vi.fn();
    renderHook(() => useHotkeys({ j: pageJ }));
    renderHook(() => useHotkeys({ j: globalJ }, { scope: "global" }));
    const dlg = document.createElement("div");
    dlg.setAttribute("role", "dialog");
    dlg.setAttribute("data-state", "open");
    document.body.appendChild(dlg);
    expect(modalOpen(document)).toBe(true);
    press("j");
    expect(pageJ).not.toHaveBeenCalled();
    expect(globalJ).toHaveBeenCalledOnce();
    dlg.remove();
    press("Shift", { shiftKey: true });
    press("j", { isComposing: true });
    const ev = new KeyboardEvent("keydown", { key: "j", cancelable: true });
    ev.preventDefault();
    act(() => {
      window.dispatchEvent(ev);
    });
    expect(pageJ).not.toHaveBeenCalled();
  });

  it("leaves Enter on buttons and links to the browser", () => {
    const enter = vi.fn();
    renderHook(() => useHotkeys({ enter }));
    const button = document.createElement("button");
    document.body.appendChild(button);
    expect(press("Enter", {}, button).defaultPrevented).toBe(false);
    expect(enter).not.toHaveBeenCalled();
    press("Enter");
    expect(enter).toHaveBeenCalledOnce();
  });

  it("can be disabled or bound to no target", () => {
    const j = vi.fn();
    const { rerender, unmount } = renderHook(({ enabled }) => useHotkeys({ j }, { enabled }), {
      initialProps: { enabled: false },
    });
    press("j");
    expect(j).not.toHaveBeenCalled();
    rerender({ enabled: true });
    press("j");
    expect(j).toHaveBeenCalledOnce();
    unmount();
    press("j");
    expect(j).toHaveBeenCalledOnce();
    renderHook(() => useHotkeys({ j }, { target: null }));
    press("j");
    expect(j).toHaveBeenCalledOnce();
  });
});

describe("useTableNav", () => {
  it("moves with j/k, clamps and opens with Enter", () => {
    const onOpen = vi.fn();
    const onSelect = vi.fn();
    const { result, rerender } = renderHook(({ n }) => useTableNav(n, { onOpen, onSelect }), {
      initialProps: { n: 3 },
    });
    expect(result.current.selected).toBeNull();
    press("Enter");
    expect(onOpen).not.toHaveBeenCalled();
    press("j");
    press("j");
    press("j");
    press("j");
    expect(result.current.selected).toBe(2);
    press("k");
    expect(result.current.selected).toBe(1);
    expect(onSelect).toHaveBeenLastCalledWith(1);
    press("Enter");
    expect(onOpen).toHaveBeenCalledWith(1);
    rerender({ n: 1 });
    expect(result.current.selected).toBe(0);
    rerender({ n: 0 });
    expect(result.current.selected).toBeNull();
    act(() => result.current.setSelected(null));
    expect(onSelect).toHaveBeenCalledTimes(5);
  });
});

class FakeSocket {
  static instances: FakeSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  closed = false;
  constructor(public url: string) {
    FakeSocket.instances.push(this);
  }
  close() {
    this.closed = true;
  }
}

describe("useCaseSocket", () => {
  beforeEach(() => {
    FakeSocket.instances = [];
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const factory = (u: string) => new FakeSocket(u) as unknown as WebSocket;

  it("connects, folds messages and reconnects with backoff", () => {
    const onMessage = vi.fn();
    const { result, unmount } = renderHook(() =>
      useCaseSocket({ url: () => "ws://x/ws?access_token=t", onMessage, socketFactory: factory }),
    );
    expect(result.current.status).toBe("connecting");
    const s = FakeSocket.instances[0];
    act(() => s?.onopen?.());
    expect(result.current.status).toBe("open");
    act(() =>
      s?.onmessage?.({
        data: JSON.stringify({ job_id: "J", step: "parse", state: "running", progress: 0.5 }),
      }),
    );
    act(() => s?.onmessage?.({ data: "garbage" }));
    expect(result.current.live.J?.parse?.progress).toBe(0.5);
    expect(onMessage).toHaveBeenCalledOnce();
    act(() => s?.onclose?.({ code: 1006 }));
    expect(result.current.status).toBe("closed");
    act(() => vi.advanceTimersByTime(600));
    expect(FakeSocket.instances).toHaveLength(2);
    unmount();
    expect(FakeSocket.instances[1]?.closed).toBe(true);
    act(() => FakeSocket.instances[1]?.onclose?.({ code: 1000 }));
  });

  it("stops on authorization close codes and when disabled", () => {
    const { result, rerender } = renderHook(({ url }) => useCaseSocket({ url, socketFactory: factory }), {
      initialProps: { url: (() => "ws://x") as (() => string) | null },
    });
    act(() => FakeSocket.instances[0]?.onclose?.({ code: 4401 }));
    expect(result.current.status).toBe("denied");
    act(() => vi.advanceTimersByTime(20_000));
    expect(FakeSocket.instances).toHaveLength(1);
    rerender({ url: null });
    expect(result.current.status).toBe("idle");
  });

  it("uses the global WebSocket by default", () => {
    const ctor = vi.fn(function (this: FakeSocket, u: string) {
      return new FakeSocket(u);
    });
    vi.stubGlobal("WebSocket", ctor);
    const { unmount } = renderHook(() => useCaseSocket({ url: () => "ws://y" }));
    expect(ctor).toHaveBeenCalledWith("ws://y");
    unmount();
    vi.unstubAllGlobals();
  });
});

describe("session hooks", () => {
  beforeEach(() => {
    clearToken();
    resetTokenMemory();
  });

  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      {children}
    </QueryClientProvider>
  );

  it("tracks the token and hydration", () => {
    const { result } = renderHook(() => ({ token: useToken(), hydrated: useHydrated() }));
    expect(result.current).toEqual({ token: null, hydrated: true });
    act(() => setToken("tok", 60));
    expect(result.current.token).toBe("tok");
    act(() => clearToken());
    expect(result.current.token).toBeNull();
  });

  it("loads /me with the token and derives case access", async () => {
    const me = {
      user_id: "alice",
      display_name: "Alice",
      is_admin: false,
      can_unmask_pii: true,
      cases: { "C-1 x": "lead" },
      signing_key_id: "k",
    };
    const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(me))));
    vi.stubGlobal("fetch", fetchMock);
    setToken("tok", 60);
    const { result } = renderHook(
      () => ({ me: useMe(), access: useAccess("C-1 x"), id: useCaseId(), kase: useCase() }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.me.data?.user_id).toBe("alice"));
    expect(result.current.access).toEqual({ userId: "alice", isAdmin: false, canUnmask: true, role: "lead" });
    expect(result.current.id).toBe("C-1 x");
    expect(result.current.kase.caseId).toBe("C-1 x");
    const headers = new Headers((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].headers);
    expect(headers.get("Authorization")).toBe("Bearer tok");
    vi.unstubAllGlobals();
  });

  it("clears the session when the API answers 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(JSON.stringify({ detail: "expired" }), { status: 401 }))),
    );
    setToken("tok", 60);
    const { result } = renderHook(() => ({ me: useMe(), token: useToken() }), { wrapper });
    await waitFor(() => expect(result.current.token).toBeNull());
    vi.unstubAllGlobals();
  });
});

describe("keyboard focus helper", () => {
  it("is exercised through fireEvent for completeness", () => {
    const fn = vi.fn();
    renderHook(() => useHotkeys({ "?": fn }, { scope: "global" }));
    fireEvent.keyDown(window, { key: "?", shiftKey: true });
    expect(fn).toHaveBeenCalledOnce();
  });
});
