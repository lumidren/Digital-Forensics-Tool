"use client";

import { useQuery } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";
import { api } from "@/lib/api-instance";
import { accessFor, type Access } from "@/lib/roles";
import { getToken, subscribeToken } from "@/lib/token-store";
import type { CaseRole, Me } from "@/lib/types";

const serverSnapshot = () => null;

/** Current bearer token (reactive). Null on the server and when signed out. */
export function useToken(): string | null {
  return useSyncExternalStore(subscribeToken, () => getToken(), serverSnapshot);
}

/** Has the client hydrated? Lets auth-dependent UI avoid a server/client mismatch. */
export function useHydrated(): boolean {
  return useSyncExternalStore(
    noopSubscribe,
    () => true,
    () => false,
  );
}

function noopSubscribe(): () => void {
  return () => undefined;
}

export function useMe() {
  const token = useToken();
  return useQuery<Me>({
    queryKey: ["me", token],
    queryFn: () => api.me(),
    enabled: token !== null,
    staleTime: 60_000,
  });
}

/** Access summary for the current user on a case (role from /me, or from the case detail). */
export function useAccess(caseId: string | null, caseRole?: CaseRole | null): Access {
  const { data } = useMe();
  return accessFor(data, caseId, caseRole);
}
