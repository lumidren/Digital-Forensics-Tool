import type { Metadata } from "next";
import { ReportsPage } from "@/components/pages/reports-page";

export const metadata: Metadata = {
  title: "Reports",
  description: "Generate and download signed case reports.",
};

export default function Page() {
  return <ReportsPage />;
}
