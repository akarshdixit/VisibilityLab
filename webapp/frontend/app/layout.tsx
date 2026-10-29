import type { Metadata } from "next";
import { Nav } from "@/components/Nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "VisibilityLab",
  description: "Quantifying Behavioral Visibility Loss Due to Malware Packing",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <aside className="side">
            <div className="brand">VisibilityLab</div>
            <div className="brand-sub">Quantifying Behavioral Visibility Loss Due to Malware Packing</div>
            <Nav />
            <div className="side-foot">
              Report processor only. Never executes, unpacks or serves samples.
            </div>
          </aside>
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
