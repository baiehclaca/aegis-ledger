import type { Metadata, Viewport } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { RevealObserver } from "@/components/Reveal";
import { PRODUCT_NAME, SITE_TITLE, SITE_URL, TITLE_TEMPLATE } from "@/lib";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });

const description = "A permissioned blockchain concept for national defense supply chains and access records. Concept draft, in development.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL + "/"),
  title: { default: SITE_TITLE, template: TITLE_TEMPLATE },
  description,
  applicationName: PRODUCT_NAME,
  alternates: { canonical: "./" },
  openGraph: { type: "website", siteName: PRODUCT_NAME, title: SITE_TITLE, description, url: "./", images: [{ url: "og.png", width: 1200, height: 630, alt: `${SITE_TITLE}.` }] },
  twitter: { card: "summary_large_image", title: PRODUCT_NAME, description, images: ["og.png"] },
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
