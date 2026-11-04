/**
 * Typed client for the Veritas API. Request bodies are typed from the generated OpenAPI schema;
 * response shapes come from `types.ts`. All requests carry the bearer token from the token store.
 */
import type {
  AdminUser,
  AnchorRecord,
  AuditRow,
  Bookmark,
  BookmarkBody,
  CaseCreateBody,
  CaseDetail,
  CaseListItem,
  CasePatchBody,
  CaseSummary,
  CustodyPage,
  CustodyVerify,
  Evidence,
  EvidenceBytes,
  EvidenceDetail,
  EvidenceUploaded,
  FacetValue,
  Finding,
  FindingActionBody,
  HistogramResult,
  Hypothesis,
  HypothesisBody,
  Ioc,
  IocImportResult,
  IocSweepResult,
  Job,
  KeyRegistry,
  LateralGraph,
  LoginResponse,
  ManualFindingBody,
  Me,
  MemberBody,
  Note,
  NoteBody,
  ProvenanceNode,
  ReportBody,
  ReportCreated,
  ReportListItem,
  ReportSignature,
  SavedView,
  SearchBody,
  SearchResult,
  StoreVerify,
  Task,
  TaskBody,
  TimelineEvent,
  UserCreateBody,
  VerifyResult,
  ViewBody,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(`${status}: ${detail}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export type QueryValue = string | number | boolean | null | undefined;

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  query?: Record<string, QueryValue>;
  body?: unknown;
  signal?: AbortSignal;
}

export interface Download {
  blob: Blob;
  filename: string;
  headers: Headers;
}

export interface UploadFields {
  kind: string;
  description?: string;
  host?: string;
  acquired_by?: string;
  tz_name?: string;
  clock_skew_ms?: number;
  expected_sha256?: string;
}

export interface UploadHandle {
  promise: Promise<EvidenceUploaded>;
  abort: () => void;
}

export interface MinimalXhr {
  open(method: string, url: string): void;
  setRequestHeader(name: string, value: string): void;
  send(body: FormData): void;
  abort(): void;
  status: number;
  responseText: string;
  upload: { onprogress: ((ev: { loaded: number; total: number; lengthComputable: boolean }) => void) | null };
  onload: (() => void) | null;
  onerror: (() => void) | null;
  onabort: (() => void) | null;
}

export interface ApiClientOptions {
  baseUrl: string;
  getToken: () => string | null;
  onUnauthorized?: () => void;
  fetchImpl?: typeof fetch;
  xhrFactory?: () => MinimalXhr;
}

export function buildQuery(query: Record<string, QueryValue> | undefined): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.append(key, String(value));
  }
  const s = params.toString();
  return s ? `?${s}` : "";
}

export function filenameFromDisposition(header: string | null, fallback: string): string {
  if (!header) return fallback;
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(header);
  return m?.[1] ? decodeURIComponent(m[1]) : fallback;
}

async function errorDetail(res: Response): Promise<string> {
  try {
    const data = (await res.json()) as { detail?: unknown };
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail)) {
      return data.detail
        .map((d: { msg?: string; loc?: unknown[] }) => `${(d.loc ?? []).slice(1).join(".")}: ${d.msg ?? ""}`)
        .join("; ");
    }
    return res.statusText || "request failed";
  } catch {
    return res.statusText || "request failed";
  }
}

const enc = encodeURIComponent;

export function createApiClient(opts: ApiClientOptions) {
  const doFetch = opts.fetchImpl ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));

  function headers(json: boolean): Headers {
    const h = new Headers();
    const token = opts.getToken();
    if (token) h.set("Authorization", `Bearer ${token}`);
    if (json) h.set("Content-Type", "application/json");
    h.set("Accept", "application/json");
    return h;
  }

  async function send(path: string, o: RequestOptions = {}): Promise<Response> {
    const res = await doFetch(`${opts.baseUrl}${path}${buildQuery(o.query)}`, {
      method: o.method ?? "GET",
      headers: headers(o.body !== undefined),
      body: o.body !== undefined ? JSON.stringify(o.body) : undefined,
      signal: o.signal,
      cache: "no-store",
    });
    if (!res.ok) {
      if (res.status === 401) opts.onUnauthorized?.();
      throw new ApiError(res.status, await errorDetail(res));
    }
    return res;
  }

  async function request<T>(path: string, o: RequestOptions = {}): Promise<T> {
    const res = await send(path, o);
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  async function download(
    path: string,
    query: Record<string, QueryValue> | undefined,
    fallback: string,
  ): Promise<Download> {
    const res = await send(path, { query });
    const blob = await res.blob();
    return {
      blob,
      filename: filenameFromDisposition(res.headers.get("Content-Disposition"), fallback),
      headers: res.headers,
    };
  }

  const c = (caseId: string) => `/api/v1/cases/${enc(caseId)}`;

  return {
    baseUrl: opts.baseUrl,
    request,
    download,

    /** Upload evidence with byte-level progress (fetch has no upload progress events). */
    uploadEvidence(
      caseId: string,
      file: File,
      fields: UploadFields,
      onProgress: (loaded: number, total: number) => void,
    ): UploadHandle {
      const factory = opts.xhrFactory ?? (() => new XMLHttpRequest() as unknown as MinimalXhr);
      const xhr = factory();
      const promise = new Promise<EvidenceUploaded>((resolve, reject) => {
        const form = new FormData();
        form.append("file", file, file.name);
        form.append("kind", fields.kind);
        for (const key of ["description", "host", "acquired_by", "tz_name", "expected_sha256"] as const) {
          const v = fields[key];
          if (v) form.append(key, v);
        }
        form.append("clock_skew_ms", String(fields.clock_skew_ms ?? 0));
        xhr.open("POST", `${opts.baseUrl}${c(caseId)}/evidence`);
        const token = opts.getToken();
        if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
        xhr.upload.onprogress = (ev) => {
          onProgress(ev.loaded, ev.lengthComputable ? ev.total : file.size);
        };
        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(JSON.parse(xhr.responseText) as EvidenceUploaded);
            return;
          }
          if (xhr.status === 401) opts.onUnauthorized?.();
          let detail = "upload failed";
          try {
            const body = JSON.parse(xhr.responseText) as { detail?: unknown };
            if (typeof body.detail === "string") detail = body.detail;
          } catch {
            /* non-JSON error body */
          }
          reject(new ApiError(xhr.status, detail));
        };
        xhr.onerror = () => reject(new ApiError(0, "network error during upload"));
        xhr.onabort = () => reject(new ApiError(0, "upload cancelled"));
        xhr.send(form);
      });
      return { promise, abort: () => xhr.abort() };
    },

    wsUrl(caseId: string): string {
      const token = opts.getToken() ?? "";
      return `${opts.baseUrl.replace(/^http/, "ws")}${c(caseId)}/ws${buildQuery({ access_token: token })}`;
    },

    // ---------------------------------------------------------------- auth
    login: (username: string, password: string) =>
      request<LoginResponse>("/api/v1/auth/login", { method: "POST", body: { username, password } }),
    me: () => request<Me>("/api/v1/me"),

    // ---------------------------------------------------------------- cases
    listCases: () => request<CaseListItem[]>("/api/v1/cases"),
    createCase: (body: CaseCreateBody) => request<CaseSummary>("/api/v1/cases", { method: "POST", body }),
    getCase: (caseId: string) => request<CaseDetail>(c(caseId)),
    patchCase: (caseId: string, body: CasePatchBody) =>
      request<CaseSummary>(c(caseId), { method: "PATCH", body }),
    setMember: (caseId: string, body: MemberBody) =>
      request<{ ok: boolean }>(`${c(caseId)}/members`, { method: "POST", body }),
    removeMember: (caseId: string, userId: string) =>
      request<{ ok: boolean }>(`${c(caseId)}/members/${enc(userId)}`, { method: "DELETE" }),
    activity: (caseId: string, limit = 50) =>
      request<AuditRow[]>(`${c(caseId)}/activity`, { query: { limit } }),

    // ---------------------------------------------------------------- evidence
    listEvidence: (caseId: string) => request<Evidence[]>(`${c(caseId)}/evidence`),
    getEvidence: (caseId: string, evId: string) =>
      request<EvidenceDetail>(`${c(caseId)}/evidence/${enc(evId)}`),
    evidenceBytes: (caseId: string, evId: string, offset: number, length: number, signal?: AbortSignal) =>
      request<EvidenceBytes>(`${c(caseId)}/evidence/${enc(evId)}/bytes`, {
        query: { offset, length },
        signal,
      }),
    verifyEvidence: (caseId: string, evId: string) =>
      request<{ ok: boolean; sha256: string }>(`${c(caseId)}/evidence/${enc(evId)}/verify`, {
        method: "POST",
      }),
    reprocessEvidence: (caseId: string, evId: string) =>
      request<{ job_id: string }>(`${c(caseId)}/evidence/${enc(evId)}/reprocess`, { method: "POST" }),
    listJobs: (caseId: string) => request<Job[]>(`${c(caseId)}/jobs`),

    // ---------------------------------------------------------------- timeline
    search: (caseId: string, body: SearchBody, signal?: AbortSignal) =>
      request<SearchResult>(`${c(caseId)}/timeline/search`, { method: "POST", body, signal }),
    histogram: (caseId: string, body: SearchBody, bucket: string | number = "auto") =>
      request<HistogramResult>(`${c(caseId)}/timeline/histogram`, {
        method: "POST",
        body,
        query: { bucket },
      }),
    facets: (caseId: string, column: string, body: SearchBody) =>
      request<FacetValue[]>(`${c(caseId)}/timeline/facets/${enc(column)}`, { method: "POST", body }),
    getEvent: (caseId: string, eventId: number, unmask = false) =>
      request<TimelineEvent>(`${c(caseId)}/events/${eventId}`, { query: { unmask: unmask || undefined } }),
    exportTimeline: (caseId: string, fmt: "csv" | "jsonl" | "plaso", unmask = false) =>
      download(
        `${c(caseId)}/timeline/export`,
        { fmt, unmask: unmask || undefined },
        `${caseId}-timeline.${fmt === "csv" ? "csv" : "jsonl"}`,
      ),
    listViews: (caseId: string) => request<SavedView[]>(`${c(caseId)}/views`),
    createView: (caseId: string, body: ViewBody) =>
      request<{ id: number }>(`${c(caseId)}/views`, { method: "POST", body }),

    // ---------------------------------------------------------------- collaboration
    listBookmarks: (caseId: string) => request<Bookmark[]>(`${c(caseId)}/bookmarks`),
    createBookmark: (caseId: string, body: BookmarkBody) =>
      request<{ id: number }>(`${c(caseId)}/bookmarks`, { method: "POST", body }),
    deleteBookmark: (caseId: string, id: number) =>
      request<{ ok: boolean }>(`${c(caseId)}/bookmarks/${id}`, { method: "DELETE" }),
    listNotes: (caseId: string, targetType?: string, targetId?: string) =>
      request<Note[]>(`${c(caseId)}/notes`, { query: { target_type: targetType, target_id: targetId } }),
    createNote: (caseId: string, body: NoteBody) =>
      request<{ id: number }>(`${c(caseId)}/notes`, { method: "POST", body }),
    listHypotheses: (caseId: string) => request<Hypothesis[]>(`${c(caseId)}/hypotheses`),
    createHypothesis: (caseId: string, body: HypothesisBody) =>
      request<{ id: number }>(`${c(caseId)}/hypotheses`, { method: "POST", body }),
    updateHypothesis: (caseId: string, id: number, body: HypothesisBody) =>
      request<Hypothesis>(`${c(caseId)}/hypotheses/${id}`, { method: "PUT", body }),
    listTasks: (caseId: string) => request<Task[]>(`${c(caseId)}/tasks`),
    createTask: (caseId: string, body: TaskBody) =>
      request<{ id: number }>(`${c(caseId)}/tasks`, { method: "POST", body }),
    updateTask: (caseId: string, id: number, body: TaskBody) =>
      request<Task>(`${c(caseId)}/tasks/${id}`, { method: "PUT", body }),

    // ---------------------------------------------------------------- findings and analytics
    runFindings: (caseId: string) =>
      request<{ proposed: number }>(`${c(caseId)}/findings/run`, { method: "POST" }),
    listFindings: (caseId: string, state?: string) =>
      request<Finding[]>(`${c(caseId)}/findings`, { query: { state } }),
    createFinding: (caseId: string, body: ManualFindingBody) =>
      request<{ id: string }>(`${c(caseId)}/findings`, { method: "POST", body }),
    findingAction: (caseId: string, findingId: string, body: FindingActionBody) =>
      request<Finding>(`${c(caseId)}/findings/${enc(findingId)}/action`, { method: "POST", body }),
    lateral: (caseId: string) => request<LateralGraph>(`${c(caseId)}/analytics/lateral`),
    provenance: (caseId: string) => request<ProvenanceNode[]>(`${c(caseId)}/analytics/provenance`),
    attackTechniques: () => request<Record<string, unknown>>("/api/v1/meta/attack"),

    // ---------------------------------------------------------------- IOCs
    listIocs: (caseId: string) => request<Ioc[]>(`${c(caseId)}/iocs`),
    importIocs: (caseId: string, text: string) =>
      request<IocImportResult>(`${c(caseId)}/iocs`, { method: "POST", body: { text } }),
    deleteIoc: (caseId: string, id: number) =>
      request<{ ok: boolean }>(`${c(caseId)}/iocs/${id}`, { method: "DELETE" }),
    sweepIocs: (caseId: string) => request<IocSweepResult>(`${c(caseId)}/iocs/sweep`, { method: "POST" }),
    stix: (caseId: string) => download(`${c(caseId)}/iocs/stix`, undefined, `${caseId}-iocs.stix.json`),

    // ---------------------------------------------------------------- custody
    custody: (
      caseId: string,
      q: { evidence_id?: string; kind?: string; limit?: number; offset?: number } = {},
    ) => request<CustodyPage>(`${c(caseId)}/custody`, { query: q }),
    verifyCustody: (caseId: string) => request<CustodyVerify>(`${c(caseId)}/custody/verify`),
    exportCustody: (caseId: string) =>
      download(`${c(caseId)}/custody/export`, undefined, `${caseId}-custody.json`),
    anchorCustody: (caseId: string) =>
      request<AnchorRecord>(`${c(caseId)}/custody/anchor`, { method: "POST" }),

    // ---------------------------------------------------------------- reports
    createReport: (caseId: string, body: ReportBody) =>
      request<ReportCreated>(`${c(caseId)}/reports`, { method: "POST", body }),
    listReports: (caseId: string) => request<ReportListItem[]>(`${c(caseId)}/reports`),
    reportSignature: (caseId: string, reportId: string) =>
      request<ReportSignature>(`${c(caseId)}/reports/${enc(reportId)}/download`, {
        query: { part: "signature" },
      }),
    downloadReport: (caseId: string, reportId: string, part: "document" | "signature") =>
      download(
        `${c(caseId)}/reports/${enc(reportId)}/download`,
        { part },
        `${reportId}.${part === "signature" ? "sig.json" : "bin"}`,
      ),

    // ---------------------------------------------------------------- admin
    listUsers: () => request<AdminUser[]>("/api/v1/admin/users"),
    createUser: (body: UserCreateBody) =>
      request<{ id: string; signing_key_id: string }>("/api/v1/admin/users", { method: "POST", body }),
    patchUser: (
      userId: string,
      body: Partial<Pick<AdminUser, "display_name" | "email" | "is_admin" | "can_unmask_pii" | "active">>,
    ) => request<{ ok: boolean }>(`/api/v1/admin/users/${enc(userId)}`, { method: "PATCH", body }),
    keys: () => request<KeyRegistry>("/api/v1/admin/keys"),
    revokeKey: (userId: string) =>
      request<{ revoked_key_id: string | null }>(`/api/v1/admin/keys/${enc(userId)}/revoke`, {
        method: "POST",
      }),
    audit: (q: { case_id?: string; actor?: string; limit?: number; offset?: number } = {}) =>
      request<AuditRow[]>("/api/v1/admin/audit", { query: q }),
    verifyAudit: () => request<VerifyResult>("/api/v1/admin/audit/verify"),
    retentionSweep: () =>
      request<{ due_for_disposal: string[] }>("/api/v1/admin/retention/sweep", { method: "POST" }),
    verifyStore: () => request<StoreVerify>("/api/v1/admin/store/verify"),
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;
