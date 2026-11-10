export const SITE_URL = (process.env.NEXT_PUBLIC_SITE_URL || "https://baiehclaca.github.io/aegis-ledger").replace(/\/$/, "");
export const BASE = process.env.NEXT_PUBLIC_BASE_PATH || "";
export const REPO = "https://github.com/baiehclaca/aegis-ledger";
export const WHITEPAPER = `${REPO}/blob/main/aegis-ledger-whitepaper.pdf`;
export const ISSUES = `${REPO}/issues`;
// TODO(Teodor): contact email not decided. Do not invent one. Set it here when chosen.
export const CONTACT_EMAIL: string | null = null;
export const NAV = [
  { href: "/government/", label: "Government" },
  { href: "/open-source/", label: "Open Source" },
  { href: "/technology/", label: "Technology" },
  { href: "/whitepaper/", label: "Whitepaper" },
  { href: "/security/", label: "Security" },
];
