import type { Metadata } from "next";
import { CONTACT_EMAIL, ISSUES, REPO } from "@/lib";
import { Button, PageHero, Rows, Section } from "@/components/ui";

export const metadata: Metadata = {
  title: "Contact",
  description: "Contact the Aegis Ledger project.",
  alternates: { canonical: "./" },
};

export default function Contact() {
  // TODO(Teodor): contact email not decided. Set CONTACT_EMAIL in lib.ts.
  return (
    <>
      <PageHero label="Contact" title="Get in touch." lead="For agencies, partners and developers." />
      <Section tone="light">
        <Rows
          arrow
          rows={[
            { title: "Email", body: CONTACT_EMAIL ? <a className="u-link" href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> : "An email address will be listed here." },
            { title: "Questions and ideas", body: <>Open an issue on <a className="u-link" href={ISSUES}>GitHub</a>.</> },
            { title: "Security problems", body: "Do not post them publicly. See the Security page." },
          ]}
        />
        <div className="mt-12 flex flex-wrap gap-4">
          <Button href={REPO} variant="line" external>GitHub repository ↗</Button>
          <Button href="/security/" variant="line">Security</Button>
        </div>
      </Section>
    </>
  );
}
