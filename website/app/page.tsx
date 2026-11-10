import { AgreementDiagram } from "@/components/Diagrams";
import { Button, Label, Note, Rows, Section, Split } from "@/components/ui";
import Link from "next/link";

export default function Home() {
  return (
    <>
      <section className="relative overflow-hidden bg-ink text-white">
        <div className="mx-auto max-w-[1440px] px-5 pb-16 pt-44 sm:px-8 md:pt-60">
          <p className="t-label rise text-ash">Permissioned ledger · In development</p>
          <h1 className="t-display rise rise-2 mt-6 max-w-[13ch]">A shared record no one can rewrite.</h1>
          <div className="mt-12 grid gap-10 md:grid-cols-12">
            <p className="t-lead rise rise-3 text-mist md:col-span-6 md:col-start-7">
              A permissioned blockchain concept for national defense supply chains and access records. Authorized parties share one consistent history. No single organization controls the record.
            </p>
          </div>
          <div className="rise rise-3 mt-12 flex flex-wrap gap-4 md:justify-end">
            <Button href="/government/">For government</Button>
            <Button href="/open-source/" variant="line">For developers</Button>
          </div>
          <div className="mt-24 overflow-hidden"><AgreementDiagram className="w-[190%] max-w-none text-white/80 sm:w-full" /></div>
          <p className="mt-4 text-[12px] text-ash">Independent nodes agree before an entry is final. Agreed entries are added to one shared history.</p>
        </div>
      </section>

      <Section tone="light">
        <Split label="The problem" title="Separate databases. Separate versions of the truth.">
          <p className="text-[17px] leading-7 opacity-80">
            Defense supply chains and sensitive systems rely on separate databases. A single compromised server can alter records, hide shipments, or erase access logs. Cross-agency visibility is slow and incomplete. Trust between organizations depends on bilateral agreements and manual audits.
          </p>
        </Split>
      </Section>

      <Section>
        <Split label="The design" title="Written once. Agreed by many. Never changed.">
          <p className="text-[17px] leading-7 text-mist">
            Each critical event — a component leaving a factory, a clearance granted, a system login — is written once. Multiple independent nodes, operated by different agencies or trusted partners, must agree before the entry is final. Once written, the entry cannot be changed or deleted.
          </p>
        </Split>
        <Rows
          rows={[
            { title: "No single point of failure or control", body: "Several independent nodes hold and agree on the record." },
            { title: "Full history, in real time", body: "The full history is visible to authorized parties as it is written." },
            { title: "Tamper-evident by design", body: "An entry cannot be changed or deleted once it is final." },
            { title: "Clear attribution", body: "Every change can be traced to who made it." },
            { title: "Alongside existing systems", body: "A layer on top of current processes. It does not replace them." },
          ]}
        />
      </Section>

      <Section tone="graphite">
        <Label>Two audiences</Label>
        <div className="mt-10 grid gap-px border hair md:grid-cols-2">
          {[
            { href: "/government/", t: "Government", b: "Supply chain provenance, access records and audit across agencies and trusted partners." },
            { href: "/open-source/", t: "Open source", b: "The whitepaper and the project live in a public GitHub repository. Follow the build, read the design, open an issue." },
          ].map((c) => (
            <Link key={c.href} href={c.href} className="reveal group block p-8 transition-colors duration-700 hover:bg-white/[0.04] md:p-12">
              <h2 className="t-title">↳ {c.t}</h2>
              <p className="mt-6 max-w-md text-[17px] leading-7 text-mist">{c.b}</p>
              <span className="u-link mt-10 inline-block text-[14px]">Read more</span>
            </Link>
          ))}
        </div>
      </Section>

      <Section>
        <Split label="Status" title="A concept in design.">
          <p className="text-[17px] leading-7 text-mist">
            The whitepaper describes a proposal for further definition. No system has been built, tested, or deployed yet. Work has started on a production build.
          </p>
          <div className="mt-8"><Button href="/technology/" variant="line">See the planned technology</Button></div>
        </Split>
        <Note>Aegis Ledger makes no claims of certification, accreditation, customers or performance.</Note>
      </Section>
    </>
  );
}
