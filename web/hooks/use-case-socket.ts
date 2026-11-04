"use client";

import { useEffect, useRef, useState } from "react";
import { applyProgress, parseProgress, type LiveProgress } from "@/lib/progress";
import type { ProgressMessage } from "@/lib/types";

export type SocketStatus = "idle" | "connecting" | "open" | "closed" | "denied";

export interface CaseSocketOptions {
  /** Build the URL at connect time so a refreshed token is used. */
  url: (() => string) | null;
  onMessage?: (msg: ProgressMessage) => void;
  socketFactory?: (url: string) => WebSocket;
  maxBackoffMs?: number;
}

/**
 * Live pipeline progress for a case over WebSocket, reconnecting with exponential backoff.
 * Close codes 4401/4404 (bad token / not a member) are final.
 */
export function useCaseSocket({ url, onMessage, socketFactory, maxBackoffMs = 15_000 }: CaseSocketOptions) {
  const [live, setLive] = useState<LiveProgress>({});
  const [status, setStatus] = useState<SocketStatus>("idle");
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;
  const urlRef = useRef(url);
  urlRef.current = url;
  const factoryRef = useRef(socketFactory);
  factoryRef.current = socketFactory;
  const enabled = url !== null;

  useEffect(() => {
    if (!enabled) {
      setStatus("idle");
      return;
    }
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;
    let stopped = false;

    const connect = () => {
      const build = urlRef.current;
      if (stopped || !build) return;
      setStatus("connecting");
      const make = factoryRef.current ?? ((u: string) => new WebSocket(u));
      ws = make(build());
      ws.onopen = () => {
        attempt = 0;
        setStatus("open");
      };
      ws.onmessage = (ev: MessageEvent) => {
        const msg = parseProgress(ev.data);
        if (!msg) return;
        setLive((s) => applyProgress(s, msg));
        onMessageRef.current?.(msg);
      };
      ws.onclose = (ev: CloseEvent) => {
        ws = null;
        if (stopped) return;
        if (ev.code === 4401 || ev.code === 4404) {
          setStatus("denied");
          return;
        }
        setStatus("closed");
        const delay = Math.min(maxBackoffMs, 500 * 2 ** attempt);
        attempt += 1;
        timer = setTimeout(connect, delay);
      };
    };
    connect();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, [enabled, maxBackoffMs]);

  return { live, status };
}
