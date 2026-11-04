"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { api } from "@/lib/api-instance";
import { useAccess } from "./use-session";

export function useCaseId(): string {
  const params = useParams<{ caseId?: string }>();
  return decodeURIComponent(params.caseId ?? "");
}

/** Case detail plus the caller's access on it. */
export function useCase() {
  const caseId = useCaseId();
  const query = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => api.getCase(caseId),
    enabled: caseId !== "",
  });
  const access = useAccess(caseId, query.data?.my_role ?? null);
  return { caseId, access, data: query.data, query };
}
