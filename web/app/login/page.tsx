import type { Metadata } from "next";
import { LoginPage } from "@/components/pages/login-page";

export const metadata: Metadata = {
  title: "Sign in",
  description: "Sign in to the Veritas DFIR examiner workspace with a local account or single sign-on.",
};

export default function Page() {
  return <LoginPage />;
}
