import type { Metadata } from "next";
import { LayerDiagram } from "@/components/Diagrams";
import { Button, Note, PageHero, Rows, Section, Split } from "@/components/ui";

export const metadata: Metadata = {
  title: "Government",
  description: "Aegis Ledger for defense supply chain provenance, access records and audit. A concept in development.",
  alternates: { canonical: "./" },
};

export default function Government() {
  return (
    <>
      <PageHero label="Government" title="One history across agencies." lead="A shared, unchangeable record of what existing systems reported. Operated by different agencies and trusted partners. Controlled by none of them alone." />

      <Section tone="light">
        <Split label="Use cases" title="Where one shared record matters." />
        <Rows
          arrow
          rows={[
            { title: "Defense supply chain provenance", body: "Record each critical supply-chain event, such as a component leaving a factory, once. Shipments cannot be hidden by changing one server.", tag: "Concept" },
            { title: "Access records", body: "Record clearances granted and system logins. Access logs cannot be erased by one compromised server.", tag: "Concept" },
            { title: "Audit", body: "Full history visible to authorized parties in real time, with clear attribution of every change. Less reliance on bilateral agreements and manual audits.", tag: "Concept" },
          ]}
        />
      </Section>

      <Section>
        <Split label="How it fits" title="A layer on top. Not a replacement.">
          <p className="text-[17px] leading-7 text-mist">
            The ledger stores only the minimum required data: identifiers, timestamps, status changes, and cryptographic hashes of supporting documents. Full documents stay in existing secure stores. The ledger records that they existed and were not altered.
          </p>
        </Split>
        <LayerDiagram className="reveal mt-20 w-full text-white/80" />
      </Section>

      <Section tone="graphite">
        <Split label="Governance" title="Many operators. One record.">
          <ul className="space-y-4 text-[17px] leading-7 text-mist">
            <li>↳ Participants run nodes.</li>
            <li>↳ Write access is limited to authorized roles.</li>
            <li>↳ Read access is granted by policy.</li>
            <li>↳ Multiple independent nodes must agree before an entry is final.</li>
          </ul>
        </Split>
      </Section>

      <Section>
        <Split label="Procurement" title="Nothing to procure yet.">
          <p className="text-[17px] leading-7 text-mist">
            Aegis Ledger is a concept in development. No system has been built, tested, or deployed. Agencies and partners who want to follow or discuss the design can get in touch.
          </p>
          <div className="mt-8 flex flex-wrap gap-4">
            <Button href="/contact/">Contact</Button>
            <Button href="/whitepaper/" variant="line">Read the whitepaper</Button>
          </div>
        </Split>
        <Note>No certifications, accreditations or authorizations are held or claimed.</Note>
      </Section>
    </>
  );
}
