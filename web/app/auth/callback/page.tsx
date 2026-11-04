import type { Metadata } from "next";
import { Suspense } from "react";
import { OidcCallback } from "@/components/pages/oidc-callback";

export const metadata: Metadata = { title: "Completing sign-in" };

export default function Page() {
  return (
    <Suspense>
      <OidcCallback />
    </Suspense>
  );
}
