import { startStack, stopStack } from "./stack";

export default async function globalSetup(): Promise<() => void> {
  stopStack();
  const state = await startStack({ reuseBuild: process.env.E2E_REUSE_BUILD === "1" });
  return () => stopStack(state);
}
