"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  LayoutDashboard, 
  Activity, 
  Globe, 
  ShieldAlert, 
  Shield,
  Zap,
  Lock,
  Scan,
  Terminal
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const navItems = [
  { href: "/overview", icon: LayoutDashboard, label: "Overview", short: "OVR" },
  { href: "/behavioral", icon: Activity, label: "Behavioral", short: "BEH" },
  { href: "/geospatial", icon: Globe, label: "Geospatial", short: "GEO" },
  { href: "/response", icon: ShieldAlert, label: "Response", short: "RES" },
  { href: "/access", icon: Lock, label: "Access IAM", short: "IAM" },
  { href: "/encoder", icon: Shield, label: "Admin Encoder", short: "ENC" },
  { href: "/decrypter", icon: Scan, label: "Decrypter", short: "ACT" },
  { href: "/attacker", icon: Terminal, label: "Attacker Sim", short: "SIM" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed top-0 left-0 w-20 h-screen glass-panel bg-slate-950/40 border-r border-white/5 flex flex-col items-center py-6 z-[9999]">
      <div className="mb-10 relative">
        <div className="h-12 w-12 rounded-sm border border-white/5 flex items-center justify-center bg-secondary shadow-sm overflow-hidden">
          <Shield className="h-6 w-6 text-slate-400" />
        </div>
      </div>

      <nav className="flex flex-col gap-4 w-full">
        {navItems.map((item) => {
          const isActive = pathname.startsWith(item.href);
          return (
            <Tooltip key={item.href}>
              <TooltipTrigger>
                 <Link
                   href={item.href}
                   className={cn(
                     "relative w-full h-16 flex flex-col items-center justify-center gap-1 transition-all duration-300 group",
                     isActive 
                       ? "text-slate-200" 
                       : "text-slate-500 hover:text-slate-300 hover:bg-white/5"
                   )}
                 >
                   <item.icon className={cn("h-6 w-6 transition-transform group-hover:scale-110", isActive && "scale-110")} />
                   <span className="text-[10px] font-bold font-heading uppercase tracking-widest">{item.short}</span>
                   
                   {isActive && (
                     <div className="absolute right-0 top-[20%] bottom-[20%] w-0.5 bg-slate-500 rounded-l-full" />
                   )}
                 </Link>
              </TooltipTrigger>
              <TooltipContent side="right" className="!bg-slate-100 !text-slate-950 border-none text-[10px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-sm shadow-xl relative z-[10000]">
                {item.label}
              </TooltipContent>
            </Tooltip>
          );
        })}
      </nav>

      <div className="mt-auto flex flex-col gap-4">
        <div className="group relative p-2 cursor-pointer text-slate-500 hover:text-slate-300 transition-colors">
            <Zap className="h-5 w-5" />
        </div>
      </div>
    </aside>
  );
}
