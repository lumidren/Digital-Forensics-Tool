import type { Metadata } from "next";
import { CasesPage } from "@/components/pages/cases-page";

export const metadata: Metadata = { title: "Cases", description: "Cases you are a member of." };

export default function Page() {
  return <CasesPage />;
}
