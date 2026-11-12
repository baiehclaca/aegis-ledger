import type { NextConfig } from "next";

// Base path: NEXT_PUBLIC_BASE_PATH wins. GITHUB_PAGES=true uses the project-site path /silver-grey-ledger.
// Plain local builds keep an empty base path for preview.
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? (process.env.GITHUB_PAGES === "true" ? "/silver-grey-ledger" : "");

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  basePath,
  env: { NEXT_PUBLIC_BASE_PATH: basePath },
  images: { unoptimized: true },
  poweredByHeader: false,
};

export default nextConfig;
