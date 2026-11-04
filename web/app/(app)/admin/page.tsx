import type { Metadata } from "next";
import { AdminPage } from "@/components/pages/admin-page";

export const metadata: Metadata = { title: "Administration", description: "Platform administration." };

export default function Page() {
  return <AdminPage />;
}
