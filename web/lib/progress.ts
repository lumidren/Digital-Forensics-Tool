/** Live processing progress: fold WebSocket messages into per-job step state and merge with `/jobs`. */
import type { Job, JobStep, ProgressMessage, StepState } from "./types";

export interface LiveStep {
  state: StepState;
  progress: number;
  message: string | null;
  error: string | null;
}

export type LiveProgress = Record<string, Record<string, LiveStep>>;

export function applyProgress(state: LiveProgress, msg: ProgressMessage): LiveProgress {
  if (!msg.job_id || !msg.step) return state;
  const job = state[msg.job_id] ?? {};
  const prev = job[msg.step];
  const step: LiveStep = {
    state: msg.state,
    progress: msg.state === "done" ? 1 : (msg.progress ?? prev?.progress ?? 0),
    message: msg.message ?? (msg.cached ? "reused cached output" : (prev?.message ?? null)),
    error: msg.error ?? null,
  };
  return { ...state, [msg.job_id]: { ...job, [msg.step]: step } };
}

export function parseProgress(data: unknown): ProgressMessage | null {
  if (typeof data !== "string") return null;
  try {
    const m = JSON.parse(data) as Partial<ProgressMessage>;
    if (typeof m.job_id === "string" && typeof m.step === "string" && typeof m.state === "string") {
      return m as ProgressMessage;
    }
  } catch {
    /* ignore malformed frames */
  }
  return null;
}

/** Overlay live step state on the polled job list. Live data wins while a job is in flight. */
export function mergeJobs(jobs: Job[], live: LiveProgress): Job[] {
  return jobs.map((job) => {
    const steps = live[job.job_id];
    if (!steps) return job;
    const merged: JobStep[] = job.steps.map((s) => {
      const l = steps[s.name];
      return l
        ? { ...s, state: l.state, progress: l.progress, message: l.error ?? l.message ?? s.message }
        : s;
    });
    for (const [name, l] of Object.entries(steps)) {
      if (!merged.some((s) => s.name === name)) {
        merged.push({
          name,
          state: l.state,
          attempts: 1,
          progress: l.progress,
          message: l.error ?? l.message,
          duration_ms: null,
        });
      }
    }
    return { ...job, steps: merged };
  });
}

export function jobFraction(job: Job): number {
  if (job.state === "done") return 1;
  if (!job.steps.length) return 0;
  const sum = job.steps.reduce(
    (s, st) => s + (st.state === "done" || st.state === "skipped" ? 1 : st.progress),
    0,
  );
  return Math.max(0, Math.min(1, sum / job.steps.length));
}

export function isActive(job: Job): boolean {
  return job.state === "pending" || job.state === "running";
}
