/** Public product name. One place to change it. British spelling: grey, never gray. */
export const PRODUCT_NAME = "Silver Grey Ledger";
export const TAGLINE = "A shared record no one can rewrite";
/** Title used for the home page, Open Graph and social cards. */
export const SITE_TITLE = `${PRODUCT_NAME} — ${TAGLINE}`;
/** Template for inner page titles, e.g. "Government — Silver Grey Ledger". */
export const TITLE_TEMPLATE = `%s — ${PRODUCT_NAME}`;

/** Public GitHub organization and repository slug. */
export const REPO_OWNER = "silvergreyhound";
export const REPO_SLUG = "silver-grey-ledger";
export const SITE_URL = (process.env.NEXT_PUBLIC_SITE_URL || `https://${REPO_OWNER}.github.io/${REPO_SLUG}`).replace(/\/$/, "");
export const BASE = process.env.NEXT_PUBLIC_BASE_PATH || "";
export const REPO = `https://github.com/${REPO_OWNER}/${REPO_SLUG}`;
export const WHITEPAPER_FILE = `${REPO_SLUG}-whitepaper.pdf`;
export const WHITEPAPER = `${REPO}/blob/main/${WHITEPAPER_FILE}`;
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

// POST-LANDING COPY: go live only once the code is in the repo.
// Pre-landing version: "No system has been built, tested, or deployed."
export const STATUS_LINE = "In development · No network has been deployed.";
