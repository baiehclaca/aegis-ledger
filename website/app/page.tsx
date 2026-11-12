import { AgreementDiagram } from "@/components/Diagrams";
import { Button, Label, Note, Rows, Section, Split } from "@/components/ui";
import Link from "next/link";
import { Mark } from "@/components/Mark";
import { PRODUCT_NAME } from "@/lib";

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
        {/* POST-LANDING COPY: go live only once the code is in the repo. Pre-landing text is in REBRAND.md. */}
        <Split label="Status" title="In development.">
          <p className="text-[17px] leading-7 text-mist">
            The whitepaper describes a proposal for further definition. A production build is in development in the public repository. No network has been deployed.
          </p>
          <div className="mt-8"><Button href="/technology/" variant="line">See the planned technology</Button></div>
        </Split>
        <Note>{PRODUCT_NAME} makes no claims of certification, accreditation, customers or performance.</Note>
      </Section>

      <Section tone="light" id="name">
        <div className="grid gap-10 md:grid-cols-12">
          <div className="md:col-span-7">
            <p className="t-label reveal opacity-60">The name</p>
            <Mark hairline className="reveal mt-10 h-24 w-24 md:h-32 md:w-32" />
            <h2 className="t-title reveal mt-8 max-w-[16ch]">Named after a courier’s token.</h2>
          </div>
          <div className="reveal space-y-6 md:col-span-5 md:pt-12">
            <p className="text-[17px] leading-7 opacity-80">
              The silver greyhound is the emblem of the King’s Messengers, the British royal and diplomatic couriers who carry private dispatches for the state. By tradition, Charles II broke four silver greyhounds from a platter and gave them to his messengers as tokens. The emblem stuck.
            </p>
            <p className="text-[17px] leading-7 opacity-80">
              In 1918 the U.S. Army formed a wartime courier service known as the Silver Greyhounds. It became the foundation of today’s U.S. Diplomatic Courier Service.
            </p>
          </div>
        </div>
        <figure className="reveal mt-20 border-t hair pt-10">
          <blockquote className="t-display max-w-[14ch]">None Swifter Than These.</blockquote>
          <figcaption className="mt-6 text-[14px] leading-6 opacity-70">Motto of the U.S. Diplomatic Courier Service, inherited from the Silver Greyhounds. From Herodotus, on the couriers of Persia.</figcaption>
        </figure>
        <Note>{PRODUCT_NAME} takes its name from this history. It is not affiliated with or endorsed by the UK or U.S. governments or their courier services.</Note>
      </Section>
    </>
  );
}
