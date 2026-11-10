import Link from "next/link";
import { NAV } from "@/lib";
import { Wordmark } from "./Mark";

export function Header() {
  return (
    <header className="absolute inset-x-0 top-0 z-30 text-white">
      <div className="border-b hair">
        <p className="mx-auto max-w-[1440px] px-5 py-2 text-[12px] text-mist sm:px-8">
          Concept draft, November 2026. In development. No system has been deployed.
        </p>
      </div>
      <nav aria-label="Main" className="mx-auto flex max-w-[1440px] items-center justify-between px-5 py-5 sm:px-8">
        <Link href="/" aria-label="Aegis Ledger, home"><Wordmark /></Link>
        <ul className="hidden items-center gap-8 lg:flex">
          {NAV.map((n) => (
            <li key={n.href}><Link href={n.href} className="u-link text-[14px] text-mist hover:text-white">{n.label}</Link></li>
          ))}
          <li>
            <Link href="/contact/" className="inline-block border border-white/70 px-5 py-2 text-[14px] transition-colors duration-500 hover:bg-white hover:text-black">Contact</Link>
          </li>
        </ul>
        <details className="group relative lg:hidden">
          <summary className="flex h-10 w-10 cursor-pointer list-none items-center justify-center border border-white/40 [&::-webkit-details-marker]:hidden" aria-label="Menu">
            <span aria-hidden className="block h-px w-4 bg-white shadow-[0_5px_0_white,0_-5px_0_white] group-open:shadow-none" />
          </summary>
          <ul className="absolute right-0 top-12 w-[min(84vw,320px)] border border-white/20 bg-ink p-2">
            {[...NAV, { href: "/contact/", label: "Contact" }].map((n) => (
              <li key={n.href}><Link href={n.href} className="block px-4 py-3 text-[16px] text-mist hover:text-white">{n.label}</Link></li>
            ))}
          </ul>
        </details>
      </nav>
    </header>
  );
}
