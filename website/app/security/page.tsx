import type { Metadata } from "next";
import { CONTACT_EMAIL, REPO } from "@/lib";
import { Note, PageHero, Rows, Section } from "@/components/ui";

export const metadata: Metadata = {
  title: "Security",
  description: "Responsible disclosure for Aegis Ledger.",
  alternates: { canonical: "./" },
};

export default function Security() {
  // TODO(Teodor): choose a private reporting channel (GitHub private vulnerability reporting is OFF on the repo; or a security email).
  const channel = CONTACT_EMAIL ? <a className="u-link" href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> : <>A private reporting channel will be listed here.</>;
  return (
    <>
      <PageHero label="Security" title="Responsible disclosure." lead="If you find a security problem in Aegis Ledger, tell us privately first." />
      <Section tone="light">
        <Rows
          rows={[
            { title: "How to report", body: <>{channel} Do not open a public GitHub issue for security problems.</> },
            { title: "What to include", body: "What you found, where, the steps to reproduce it, and the impact you expect." },
            { title: "Scope", body: <>The source in the <a className="u-link" href={REPO}>GitHub repository</a> and this website. No Aegis Ledger system is deployed, so there are no live systems to test.</> },
            { title: "Rules", body: "Only test what you own. Do not access, change or delete other people's data. Give reasonable time to fix a problem before you share it." },
            { title: "Cryptography", body: "Aegis Ledger uses no home-made cryptography. Only standardized algorithms are planned: ML-DSA (FIPS 204), SLH-DSA (FIPS 205) and SHA-3." },
          ]}
        />
        <Note>There is no bug bounty.</Note>
      </Section>
    </>
  );
}
