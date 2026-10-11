import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelSOC - Autonomous Threat Intelligence Platform",
  description: "Enterprise web application log parsing, real-time feature extraction, Isolation Forest anomaly scoring, and multi-class cyberattack classification.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark h-full antialiased">
      <body className="min-h-full flex flex-col bg-[#090d16] text-[#f1f5f9]">
        {children}
      </body>
    </html>
  );
}
