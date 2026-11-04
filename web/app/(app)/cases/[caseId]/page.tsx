import type { Metadata } from "next";
import { DashboardPage } from "@/components/pages/dashboard-page";

export const metadata: Metadata = {
  title: "Case dashboard",
  description: "Case overview: evidence, events, findings and processing.",
};

export default function Page() {
  return <DashboardPage />;
}
