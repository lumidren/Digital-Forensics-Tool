import type { Metadata } from "next";
import { GraphPage } from "@/components/pages/graph-page";

export const metadata: Metadata = {
  title: "Graphs",
  description: "Lateral movement and file provenance graphs.",
};

export default function Page() {
  return <GraphPage />;
}
