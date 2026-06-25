import "./globals.css";
import type { Metadata } from "next";
import { Providers } from "./providers";
import { Sidebar } from "@/components/Sidebar";

export const metadata: Metadata = {
  title: "SOC PARALLAX",
  description: "Cyber Behavioral Intelligence Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-mono">
        <Providers>
          <div className="flex">
            <Sidebar />
            <main className="flex-1 min-h-screen p-8 max-w-[1400px]">{children}</main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
