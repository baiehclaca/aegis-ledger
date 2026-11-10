import Link from "next/link";
import { NAV, REPO } from "@/lib";
import { Wordmark } from "./Mark";

export function Footer() {
  return (
    <footer className="bg-ink text-white">
      <div className="mx-auto max-w-[1440px] px-5 pb-12 pt-24 sm:px-8">
        <div className="grid gap-12 border-t hair pt-10 md:grid-cols-12">
          <div className="md:col-span-6">
            <Wordmark />
            <p className="mt-6 max-w-sm text-[14px] leading-6 text-ash">
              A permissioned blockchain concept for national defense supply chains and access records.
            </p>
          </div>
          <nav aria-label="Footer" className="md:col-span-3">
            <p className="t-label text-ash">Pages</p>
            <ul className="mt-4 space-y-2 text-[14px]">
              {[...NAV, { href: "/contact/", label: "Contact" }].map((n) => (
                <li key={n.href}><Link href={n.href} className="u-link text-mist hover:text-white">{n.label}</Link></li>
              ))}
            </ul>
          </nav>
          <div className="md:col-span-3">
            <p className="t-label text-ash">Source</p>
            <ul className="mt-4 space-y-2 text-[14px]">
              <li><a href={REPO} className="u-link text-mist hover:text-white">GitHub repository ↗</a></li>
              <li className="text-ash">License: not chosen yet</li>
            </ul>
          </div>
        </div>
        <p className="mt-16 text-[12px] text-ash">Aegis Ledger · Concept draft · November 2026 · No system has been built, tested, or deployed.</p>
      </div>
    </footer>
  );
}
