import type { Metadata } from "next";
import { Suspense } from "react";
import { FindingsPage } from "@/components/pages/findings-page";

export const metadata: Metadata = {
  title: "Findings",
  description: "Findings review, hypotheses and tasks.",
};

export default function Page() {
  return (
    <Suspense>
      <FindingsPage />
    </Suspense>
  );
}
