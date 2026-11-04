import type { Metadata } from "next";
import { Suspense } from "react";
import { TimelinePage } from "@/components/pages/timeline-page";

export const metadata: Metadata = {
  title: "Timeline",
  description: "Search, filter and pivot across the case super-timeline.",
};

export default function Page() {
  return (
    <Suspense>
      <TimelinePage />
    </Suspense>
  );
}
