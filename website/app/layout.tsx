import type { Metadata, Viewport } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { RevealObserver } from "@/components/Reveal";
import { SITE_URL } from "@/lib";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });

const description = "A permissioned blockchain concept for national defense supply chains and access records. Concept draft, in development.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL + "/"),
  title: { default: "Aegis Ledger — A shared record no one can rewrite", template: "%s — Aegis Ledger" },
  description,
  applicationName: "Aegis Ledger",
  alternates: { canonical: "./" },
  openGraph: { type: "website", siteName: "Aegis Ledger", title: "Aegis Ledger — A shared record no one can rewrite", description, url: "./", images: [{ url: "og.png", width: 1200, height: 630, alt: "Aegis Ledger — A shared record no one can rewrite." }] },
  twitter: { card: "summary_large_image", title: "Aegis Ledger", description, images: ["og.png"] },
  robots: { index: true, follow: true },
};

export const viewport: Viewport = { themeColor: "#0b0c0d", colorScheme: "dark light" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={inter.variable} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: "document.documentElement.classList.add('js')" }} />
      </head>
      <body className="bg-ink font-sans text-white">
        <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:bg-white focus:px-4 focus:py-2 focus:text-black">Skip to content</a>
        <Header />
        <main id="main">{children}</main>
        <Footer />
        <RevealObserver />
      </body>
    </html>
  );
}
