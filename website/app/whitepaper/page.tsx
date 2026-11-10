import type { Metadata } from "next";
import { WHITEPAPER } from "@/lib";
import { Button, PageHero, Rows, Section } from "@/components/ui";

export const metadata: Metadata = {
  title: "Whitepaper",
  description: "Summary of the Aegis Ledger concept draft, November 2026.",
  alternates: { canonical: "./" },
};

export default function Whitepaper() {
  return (
    <>
      <PageHero label="Whitepaper · Concept draft · November 2026" title="The concept, in six parts." lead="A summary of the Aegis Ledger whitepaper. The full text is in the GitHub repository.">
        <div className="mt-8"><Button href={WHITEPAPER} external>Read on GitHub ↗</Button></div>
      </PageHero>
      <Section tone="light">
        <Rows
          rows={[
            { title: "Overview", body: "A permissioned blockchain used as an immutable national ledger. It records critical defense supply-chain events and system access logs. Authorized parties share one consistent history. No single organization controls the record." },
            { title: "Problem", body: "Separate databases. A single compromised server can alter records, hide shipments, or erase access logs. Cross-agency visibility is slow and incomplete. Trust depends on bilateral agreements and manual audits." },
            { title: "Solution", body: "Each critical event is written once. Multiple independent nodes, operated by different agencies or trusted partners, must agree before the entry is final. Once written, it cannot be changed or deleted." },
            { title: "How it works", body: "Participants run nodes. Write access is limited to authorized roles; read access is granted by policy. Only identifiers, timestamps, status changes and document hashes are stored. The system is a layer on top of current processes." },
            { title: "Properties", body: "No single point of failure or control. Full history visible to authorized parties in real time. Tamper-evident by design. Clear attribution of every change. Operates alongside existing infrastructure." },
            { title: "Status", body: "A concept in design. No system has been built, tested, or deployed. The architecture is a proposal for further definition." },
          ]}
        />
      </Section>
    </>
  );
}
