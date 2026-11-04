import type { Metadata } from "next";
import { MemoryPage } from "@/components/pages/memory-page";

export const metadata: Metadata = {
  title: "Memory analysis",
  description: "Process tree and memory anomaly flags.",
};

export default function Page() {
  return <MemoryPage />;
}
