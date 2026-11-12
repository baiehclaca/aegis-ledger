import type { Metadata } from "next";
import { ISSUES, PRODUCT_NAME, REPO, WHITEPAPER_FILE } from "@/lib";
import { Button, Note, PageHero, Rows, Section, Split } from "@/components/ui";

export const metadata: Metadata = {
  title: "Open Source",
  description: `${PRODUCT_NAME} is developed in a public GitHub repository. Read the design, follow the build, open an issue.`,
  alternates: { canonical: "./" },
};

function Cmd({ children }: { children: string }) {
  return <p className="border hair px-5 py-4 text-[15px] tracking-[-0.005em] text-white">{children}</p>;
}

export default function OpenSource() {
  return (
    <>
      <PageHero label="Open source" title="Built in the open." lead="The design and the project live in a public repository on GitHub.">
        <div className="mt-8"><Button href={REPO} external>GitHub repository ↗</Button></div>
      </PageHero>

      <Section tone="light">
        {/* POST-LANDING COPY: go live only once the code is in the repo. Pre-landing text is in REBRAND.md. */}
        <Split label="In the repository" title="The whitepaper, the code and this site.">
          <ul className="space-y-3 text-[17px] leading-7 opacity-80">
            <li>↳ {WHITEPAPER_FILE} — the concept draft, November 2026.</li>
            <li>↳ README.md — a short description.</li>
            <li>↳ The source of the production build, in development.</li>
            <li>↳ The source of this website, served by GitHub Pages.</li>
          </ul>
        </Split>
        <Rows
          rows={[
            { title: "License", body: "Apache-2.0.", tag: "Open" },
            { title: "Status", body: "A production build is in development in this repository. No network has been deployed.", tag: "In development" },
          ]}
        />
      </Section>

      <Section>
        <Split label="Planned build" title="What is being built.">
          <p className="text-[17px] leading-7 text-mist">These are the decisions for the production build. They are in development and not released.</p>
        </Split>
        <Rows
          rows={[
            { title: "Agreement engine", body: "Its own Byzantine fault tolerant (BFT) agreement engine, written in Go.", tag: "In development" },
            { title: "Signatures", body: "Standardized post-quantum signatures: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).", tag: "In development" },
            { title: "Hashing", body: "SHA-3.", tag: "In development" },
            { title: "No home-made cryptography", body: "Only standardized algorithms are used.", tag: "Rule" },
            { title: "Interfaces", body: "Command line and API first. A dashboard comes later.", tag: "In development" },
          ]}
        />
      </Section>

      <Section tone="graphite">
        <Split label="Run and build" title="Get the source.">
          <div className="space-y-4">
            <Cmd>{`git clone ${REPO}.git`}</Cmd>
            <p className="text-[15px] leading-6 text-mist">The production build is in development and not released. See the README in the repository for its current state.</p>
          </div>
        </Split>
      </Section>

      <Section>
        <Split label="Contribute" title="How to help today.">
          <ul className="space-y-4 text-[17px] leading-7 text-mist">
            <li>↳ Read the whitepaper and question the design.</li>
            <li>↳ Open an issue on GitHub for ideas, questions or mistakes.</li>
            <li>↳ Report security problems privately. See the Security page.</li>
          </ul>
          <div className="mt-8 flex flex-wrap gap-4">
            <Button href={ISSUES} external>Open an issue ↗</Button>
            <Button href="/security/" variant="line">Security</Button>
          </div>
        </Split>
        <Note>There are no contribution guidelines yet.</Note>
      </Section>
    </>
  );
}
