import type { ReactNode } from "react";
import Link from "next/link";

export function Section({ tone = "dark", children, className = "", id }: { tone?: "dark" | "light" | "graphite"; children: ReactNode; className?: string; id?: string }) {
  const t = tone === "light" ? "on-light bg-paper text-ink" : tone === "graphite" ? "bg-graphite text-white" : "bg-ink text-white";
  return (
    <section id={id} className={`${t} ${className}`}>
      <div className="mx-auto max-w-[1440px] px-5 py-24 sm:px-8 md:py-36">{children}</div>
    </section>
  );
}

export function Label({ children }: { children: ReactNode }) {
  return <p className="t-label reveal opacity-60">{children}</p>;
}

/** Split: title on the left, lead text in the right column. */
export function Split({ label, title, children }: { label?: string; title: ReactNode; children?: ReactNode }) {
  return (
    <div className="grid gap-10 md:grid-cols-12">
      <div className="md:col-span-7">
        {label && <Label>{label}</Label>}
        <h2 className="t-title reveal mt-6 max-w-[16ch]">{title}</h2>
      </div>
      {children && <div className="reveal md:col-span-5 md:pt-12">{children}</div>}
    </div>
  );
}

export type Row = { title: string; body: ReactNode; tag?: string };

/** Numbered hairline rows: /01 ... */
export function Rows({ rows, arrow = false }: { rows: Row[]; arrow?: boolean }) {
  return (
    <ol className="mt-16 border-t hair">
      {rows.map((r, i) => (
        <li key={r.title} className="reveal grid gap-4 border-b hair py-8 md:grid-cols-12 md:py-10">
          <span className="text-[12px] tabular-nums opacity-50 md:col-span-1">{arrow ? "↳" : `/${String(i + 1).padStart(2, "0")}`}</span>
          <h3 className="text-[22px] leading-7 tracking-[-0.02em] md:col-span-4 md:text-[26px] md:leading-8">{r.title}</h3>
          <div className={`text-[16px] leading-7 opacity-75 ${r.tag ? "md:col-span-5" : "md:col-span-7"}`}>{r.body}</div>
          {r.tag && <span className="t-label self-start opacity-60 md:col-span-2 md:text-right">{r.tag}</span>}
        </li>
      ))}
    </ol>
  );
}

export function PageHero({ label, title, lead, children }: { label: string; title: ReactNode; lead: ReactNode; children?: ReactNode }) {
  return (
    <section className="bg-ink text-white">
      <div className="mx-auto grid max-w-[1440px] gap-10 px-5 pb-20 pt-44 sm:px-8 md:grid-cols-12 md:pb-32 md:pt-56">
        <div className="md:col-span-8">
          <p className="t-label rise text-ash">{label}</p>
          <h1 className="t-display rise rise-2 mt-6">{title}</h1>
        </div>
        <div className="rise rise-3 md:col-span-4 md:self-end">
          <p className="t-lead text-mist">{lead}</p>
          {children}
        </div>
      </div>
    </section>
  );
}

export function Button({ href, children, variant = "solid", external = false }: { href: string; children: ReactNode; variant?: "solid" | "line"; external?: boolean }) {
  const base = "inline-flex items-center gap-3 px-6 py-3 text-[15px] transition-colors duration-500";
  const v = variant === "solid" ? "bg-white text-black hover:bg-mist" : "btn-line border border-current hover:bg-white hover:text-black";
  if (href.startsWith("/")) return <Link href={href} className={`${base} ${v}`}>{children}</Link>;
  return <a href={href} className={`${base} ${v}`} {...(external ? { rel: "noopener noreferrer" } : {})}>{children}</a>;
}

export function Note({ children }: { children: ReactNode }) {
  return <p className="reveal mt-12 max-w-2xl border-l hair pl-5 text-[14px] leading-6 opacity-70">{children}</p>;
}
