import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/Sidebar";

export const metadata: Metadata = {
  title: "AiFw — AI-Powered Firewall",
  description: "FreeBSD firewall management interface",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <div className="flex min-h-screen">
          <Sidebar />
          <main className="flex-1 ml-56 p-6 overflow-auto">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
