import type { MetadataRoute } from "next";
import { SITE_URL } from "@/lib";

export const dynamic = "force-static";

export default function sitemap(): MetadataRoute.Sitemap {
  return ["", "government/", "open-source/", "technology/", "whitepaper/", "security/", "contact/"].map((p) => ({
    url: `${SITE_URL}/${p}`,
    changeFrequency: "monthly",
    priority: p === "" ? 1 : 0.7,
  }));
}
