import type { Metadata } from "next";
import { EvidenceDetailPage } from "@/components/pages/evidence-detail-page";

export const metadata: Metadata = {
  title: "Evidence detail",
  description: "Evidence hashes, custody entry, integrity and bytes.",
};

export default function Page() {
  return <EvidenceDetailPage />;
}
