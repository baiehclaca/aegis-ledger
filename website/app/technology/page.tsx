import type { Metadata } from "next";
import { AgreementDiagram, LayerDiagram } from "@/components/Diagrams";
import { Note, PageHero, Rows, Section, Split } from "@/components/ui";

export const metadata: Metadata = {
  title: "Technology",
  description: "High-level architecture of Aegis Ledger: permissioned network, BFT agreement, post-quantum signatures, SHA-3 and tamper-evidence.",
  alternates: { canonical: "./" },
};

export default function Technology() {
  return (
    <>
      <PageHero label="Technology" title="Simple parts. Standard cryptography." lead="A high-level view of the design. Mechanism details are not published here." />

      <Section tone="light">
        <Split label="Architecture" title="Five layers of one record." />
        <Rows
          rows={[
            { title: "Permissioned network", body: "Participants run nodes. Write access is limited to authorized roles. Read access is granted by policy.", tag: "Whitepaper" },
            { title: "Agreement", body: "Multiple independent nodes, operated by different agencies or trusted partners, must agree before an entry is final. Planned as its own Byzantine fault tolerant (BFT) engine, written in Go.", tag: "In development" },
            { title: "Signatures", body: "Standardized post-quantum signatures: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). No home-made cryptography.", tag: "In development" },
            { title: "Hashing", body: "SHA-3. The ledger stores cryptographic hashes of supporting documents, not the documents.", tag: "In development" },
            { title: "Tamper-evidence", body: "Each entry is written once. Once final, it cannot be changed or deleted. Every change has clear attribution.", tag: "Whitepaper" },
          ]}
        />
      </Section>

      <Section>
        <Split label="Agreement" title="No single node decides.">
          <p className="text-[17px] leading-7 text-mist">No single organization controls the record. There is no single point of failure or control.</p>
        </Split>
        <div className="mt-20 overflow-hidden"><AgreementDiagram className="w-[190%] max-w-none text-white/80 sm:w-full" /></div>
      </Section>

      <Section tone="graphite">
        <Split label="Data" title="Only the minimum on the ledger.">
          <p className="text-[17px] leading-7 text-mist">Identifiers, timestamps, status changes, and cryptographic hashes of supporting documents. Full documents stay in existing secure stores. The ledger records that they existed and were not altered.</p>
        </Split>
        <LayerDiagram className="reveal mt-20 w-full text-white/80" />
      </Section>

      <Section>
        <Split label="Interfaces" title="Command line and API first.">
          <p className="text-[17px] leading-7 text-mist">A dashboard comes later.</p>
        </Split>
        <Note>No performance figures are published. None have been measured, because no system has been built, tested, or deployed.</Note>
      </Section>
    </>
  );
}
