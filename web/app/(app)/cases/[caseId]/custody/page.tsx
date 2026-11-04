import type { Metadata } from "next";
import { Suspense } from "react";
import { CustodyPage } from "@/components/pages/custody-page";

export const metadata: Metadata = {
  title: "Chain of custody",
  description: "Custody ledger entries, verification and export.",
};

export default function Page() {
  return (
    <Suspense>
      <CustodyPage />
    </Suspense>
  );
}
