import type { Metadata } from "next";
import { EvidencePage } from "@/components/pages/evidence-page";

export const metadata: Metadata = { title: "Evidence", description: "Evidence intake and processing queue." };

export default function Page() {
  return <EvidencePage />;
}
