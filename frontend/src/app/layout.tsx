import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Sentinel SOC | Insider Threat Command Center",
  description: "High-fidelity SOC dashboard for real-time insider threat detection and response.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} dark h-full antialiased`}
    >
      <body className="min-h-full bg-background text-foreground font-sans overflow-x-hidden selection:bg-neon-cyan/30">
        <TooltipProvider>
          <Sidebar />
          <TopBar />
          <main className="flex-1 pl-20 pt-16 min-h-screen">
            <div className="max-w-[1600px] mx-auto p-8">
              {children}
            </div>
          </main>
        </TooltipProvider>
      </body>
    </html>
  );
}
