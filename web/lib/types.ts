/**
 * Response shapes of the Veritas API.
 *
 * Request bodies come from the generated OpenAPI schema (`api-schema.d.ts`). Most routes return
 * plain dicts without a response model, so their shapes are declared here, mirroring
 * `python/veritas/api/main.py`.
 */
import type { components } from "./api-schema";

export type Schemas = components["schemas"];
export type SearchBody = Schemas["SearchIn"];
export type CaseCreateBody = Schemas["CaseIn"];
export type CasePatchBody = Schemas["CasePatch"];
export type MemberBody = Schemas["MemberIn"];
export type UserCreateBody = Schemas["UserIn"];
export type BookmarkBody = Schemas["BookmarkIn"];
export type NoteBody = Schemas["NoteIn"];
export type HypothesisBody = Schemas["HypothesisIn"];
export type TaskBody = Schemas["TaskIn"];
export type FindingActionBody = Schemas["FindingAction"];
export type ManualFindingBody = Schemas["ManualFindingIn"];
export type ReportBody = Schemas["ReportIn"];
export type ViewBody = Schemas["ViewIn"];

export const CASE_ROLES = ["viewer", "examiner", "reviewer", "lead"] as const;
export type CaseRole = (typeof CASE_ROLES)[number];

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_STATES = ["proposed", "confirmed", "approved", "rejected"] as const;
export type FindingState = (typeof FINDING_STATES)[number];

export interface LoginResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
}

export interface Me {
  user_id: string;
  display_name: string;
  is_admin: boolean;
  can_unmask_pii: boolean;
  cases: Record<string, CaseRole>;
  signing_key_id: string;
}

export interface CaseSummary {
  id: string;
  name: string;
  description: string;
  status: "open" | "review" | "closed" | "disposed";
  created_by: string;
  created: string;
  timezone: string | null;
  legal_hold: boolean;
  retention_until: string | null;
  ledger_id: string;
  disposed_at?: string | null;
  disposed_by?: string | null;
  disposal_reason?: string | null;
}

export interface CaseListItem extends CaseSummary {
  evidence_count: number;
  finding_count: number;
  event_count: number;
}

export interface CaseMember {
  user_id: string;
  role: CaseRole;
}

export interface CaseDetail extends CaseSummary {
  members: CaseMember[];
  my_role: CaseRole;
  event_count: number;
}

export interface Evidence {
  id: string;
  case_id: string;
  sha256: string;
  md5: string;
  sha3_256: string;
  size: number;
  name: string;
  kind: string;
  description: string;
  host: string | null;
  acquired_by: string | null;
  tz_name: string | null;
  clock_skew_ms: number;
  ingest_entry_hash: string;
  ingested: string;
  status: string;
}

export interface EvidenceUploaded extends Evidence {
  job_id: string;
  classified_as: string;
}

export type StepState = "pending" | "running" | "done" | "failed" | "skipped";

export interface JobStep {
  name: string;
  state: StepState;
  attempts: number;
  progress: number;
  message: string | null;
  duration_ms: number | null;
}

export interface Job {
  job_id: string;
  case_id: string;
  evidence_sha256: string;
  kind: string;
  priority: number;
  state: StepState;
  created: string;
  updated: string;
  error: string | null;
  steps: JobStep[];
}

export interface EvidenceDetail extends Evidence {
  jobs: Job[];
}

export interface ProgressMessage {
  job_id: string;
  step: string;
  state: StepState;
  progress?: number;
  message?: string;
  error?: string;
  cached?: boolean;
}

export interface EvidenceBytes {
  offset: number;
  length: number;
  hex: string;
  size: number;
}

export type AttrValue = string | number | boolean | null | AttrValue[] | { [key: string]: AttrValue };

export interface TimelineEvent {
  id: number;
  data_type: string;
  timestamp_desc: string;
  message: string;
  timestamp: number | null;
  source_short: string;
  source_long: string;
  evidence_sha256: string;
  evidence_path: string;
  offset: number;
  parser: string;
  parser_version: string;
  host?: string;
  user?: string;
  timezone?: string;
  skew_ns: number;
  attrs: Record<string, AttrValue>;
}

export interface SearchResult {
  total: number;
  events: TimelineEvent[];
  ms: number;
}

export interface HistogramBucket {
  start_ns: number;
  count: number;
}

export interface HistogramResult {
  bucket_ns: number;
  buckets: HistogramBucket[];
}

export interface FacetValue {
  value: string;
  count: number;
}

export interface SavedView {
  id: number;
  name: string;
  query: Record<string, unknown>;
  user_id: string;
}

export interface Bookmark {
  id: number;
  event_id: number;
  label: string;
  tags: string[];
  user_id: string;
  created: string;
}

export interface Note {
  id: number;
  user_id: string;
  target_type: "case" | "event" | "evidence" | "finding" | "hypothesis";
  target_id: string;
  body: string;
  created: string;
}

export interface Hypothesis {
  id: number;
  case_id: string;
  user_id: string;
  title: string;
  statement: string;
  status: "open" | "supported" | "refuted";
  supporting_event_ids: number[];
  refuting_event_ids: number[];
  created?: string;
}

export interface Task {
  id: number;
  case_id: string;
  created_by: string;
  title: string;
  detail: string;
  assignee: string | null;
  status: "todo" | "doing" | "done";
  due: string | null;
}

export interface Finding {
  id: string;
  case_id: string;
  rule: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  category: string;
  attack_techniques: string[];
  event_ids: number[];
  evidence_sha256: string[];
  details: Record<string, unknown>;
  first_ns: number | null;
  last_ns: number | null;
  state: FindingState;
  origin: "rule" | "manual";
  confirmed_by: string | null;
  confirmed_at: string | null;
  approved_by: string | null;
  approved_at: string | null;
  examiner_rationale: string | null;
  reviewer_comment: string | null;
}

export interface LateralEdge {
  src: string;
  dst: string;
  user: string;
  technique: string;
  kind: string;
  count: number;
  event_ids: number[];
  first_ns: number | null;
  last_ns: number | null;
}

export interface LateralGraph {
  nodes: { id: string }[];
  edges: LateralEdge[];
}

export interface ProvenanceNode {
  path: string;
  origin: string | null;
  origin_kind: string | null;
  events: Record<string, number[]>;
  first_ns: number | null;
}

export interface Ioc {
  id: number;
  ioc_id: string;
  ioc_type: string;
  value: string;
  source: string;
  tags: string[];
  hits: number;
}

export interface IocImportResult {
  added: number;
  total: number;
}

export interface IocSweepResult {
  hits: Record<string, unknown>[];
  total: number;
  by_ioc: Record<string, number>;
}

export interface CustodyEntry {
  seq: number;
  ledger_id: string;
  kind: string;
  actor: string;
  purpose: string;
  timestamp?: string;
  evidence_id?: string | null;
  hashes?: Record<string, string | number> | null;
  details?: Record<string, unknown>;
  entry_hash: string;
  prev_hash?: string;
  [key: string]: unknown;
}

export interface CustodyPage {
  total: number;
  entries: CustodyEntry[];
}

export interface CustodyVerify {
  verdict: "PASS" | "FAIL";
  failures: string[];
  entries: number;
  head_hash: string | null;
}

export interface AnchorRecord {
  ledger_id: string;
  seq: number;
  head_hash: string;
  anchored_at: string;
  sink: string;
  receipt: string | null;
}

export interface ReportCreated {
  id: string;
  report_sha256: string;
  state_hash: string;
  signer: string;
  signer_key_id: string;
  signer_public_key: string;
  signature_ed25519: string;
  format: "pdf" | "docx";
  case_id: string;
  ledger_entry_hash: string;
  size: number;
}

export interface ReportListItem {
  id: string;
  format: "pdf" | "docx";
  sha256: string;
  state_hash: string;
  created_by: string;
  created: string;
  ledger_entry_hash: string;
}

export interface ReportSignature {
  report_sha256: string;
  state_hash: string;
  signer: string;
  signer_key_id: string;
  signer_public_key: string;
  signature_ed25519: string;
  format: string;
  case_id: string;
}

export interface AdminUser {
  id: string;
  display_name: string;
  email: string | null;
  is_admin: boolean;
  can_unmask_pii: boolean;
  active: boolean;
}

export interface KeyRecord {
  key_id: string;
  holder: string;
  role: string;
  public_key?: string;
  valid_from?: string;
  valid_to?: string | null;
  [key: string]: unknown;
}

export interface KeyRegistry {
  keys: KeyRecord[];
}

export interface AuditRow {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  case_id: string | null;
  target: string | null;
  detail: Record<string, unknown>;
  prev_hash: string;
  row_hash: string;
}

export interface VerifyResult {
  ok: boolean;
  failures: unknown[];
}

export interface StoreVerify {
  objects: number;
  failed: { address: string; ok: boolean }[];
}

// ------------------------------------------------------------------ retention disposal
export interface RetentionDueCase {
  id: string;
  name: string;
  retention_until: string | null;
  status: string;
}

export interface RetentionSweep {
  due_for_disposal: string[];
  cases?: RetentionDueCase[];
}

export interface DisposalObject {
  address: string;
  sha256: string;
  md5: string | null;
  sha3_256: string | null;
  size: number;
  encrypted: boolean | null;
  present: boolean;
  object_lock_until: string | null;
  evidence_id?: string;
  name?: string;
  role?: "primary" | "segment";
}

export interface DisposalCasePlan {
  case_id: string;
  name: string;
  retention_until: string | null;
  ledger_id: string;
  evidence_objects: DisposalObject[];
  derived_objects: DisposalObject[];
  kept_shared: { address: string; evidence_id: string | null; referenced_by: string[] }[];
  timeline_events: number;
  report_files: { file: string; size: number; sha256: string }[];
  intake_sessions: { session_id: string; files: number; bytes: number }[];
  pending_jobs: string[];
  db_rows: Record<string, number>;
  memberships_kept: string[];
  bytes: number;
}

export interface DisposalPlan {
  dry_run: true;
  plan_sha256: string;
  confirmation_token: string;
  expires_at: string;
  confirm_phrases: string[];
  cases: DisposalCasePlan[];
}

export interface DisposalCaseResult {
  case_id: string;
  status: "disposed";
  disposed_at: string;
  intent_entry_hash: string;
  completed_entry_hash: string;
  objects_deleted: string[];
  retained_by_object_lock: string[];
  delete_denied: string[];
  objects_missing: string[];
  kept_shared: string[];
  timeline_events_deleted: number;
  db_rows_deleted: Record<string, number>;
  bytes_deleted: number;
}

export interface DisposalResult {
  dry_run: false;
  plan_sha256: string;
  disposed: DisposalCaseResult[];
}
