import type { NextConfig } from "next";

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
];

const nextConfig: NextConfig = {
  // E2E and Lighthouse builds bake a different API URL into a separate output directory.
  distDir: process.env.NEXT_DIST_DIR ?? ".next",
  // Self-contained server for the container image (deploy/docker/Dockerfile.web copies .next/standalone).
  output: "standalone",
  // Trace from this package so server.js lands at .next/standalone/server.js wherever it is built.
  outputFileTracingRoot: __dirname,
  reactStrictMode: true,
  poweredByHeader: false,
  productionBrowserSourceMaps: true,
  eslint: { ignoreDuringBuilds: true },
  headers() {
    return Promise.resolve([{ source: "/:path*", headers: securityHeaders }]);
  },
};

export default nextConfig;
