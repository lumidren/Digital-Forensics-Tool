import type { Metadata } from "next";
import { IocsPage } from "@/components/pages/iocs-page";

export const metadata: Metadata = { title: "IOCs", description: "Indicator import, sweep and STIX export." };

export default function Page() {
  return <IocsPage />;
}
