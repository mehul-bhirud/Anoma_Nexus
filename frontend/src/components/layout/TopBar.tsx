"use client";

import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import { 
  Bell, 
  Search, 
  Terminal,
  ChevronRight
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAegisStream } from "@/hooks/use-aegis-stream";

export function TopBar() {
  const pathname = usePathname();
  const pageName = pathname.split("/").pop() || "Dashboard";
  const { connectionStatus: isConnected, isIntegrityVerified: isVerified, merkleRoot } = useAegisStream();

  const [time, setTime] = useState<string>("00:00:00 UTC");
  useEffect(() => {
    const updateTime = () => setTime(new Date().toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' }) + ' UTC');
    const timer = setInterval(updateTime, 1000);
    updateTime();
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="fixed top-0 left-0 w-full h-16 glass-panel bg-card/40 border-b border-white/5 flex items-center justify-between px-6 pl-24 z-[9998]">
      <div className="flex items-center gap-4">
        <div className="flex flex-col">
          <span className="text-[10px] font-black font-heading uppercase tracking-[0.3em] text-primary leading-none">Aegis-Fusion</span>
          <span className="text-[8px] font-bold font-heading uppercase tracking-[0.1em] text-slate-500 mt-1">Williams-Sonoma Corp</span>
        </div>
        <div className="w-px h-6 bg-white/5 mx-2" />
        <h1 className="text-sm font-black font-heading uppercase tracking-widest text-slate-100 flex items-center gap-2">
          {pageName}
          <div className="w-1.5 h-1.5 rounded-full bg-primary/40" />
        </h1>
      </div>

      <div className="flex items-center gap-6">
        {/* AEGIS-FUSION Status Hub */}
        <div className="flex items-center gap-4 bg-slate-950/40 border border-white/[0.03] px-4 py-1.5 rounded-sm">
          <div className="flex items-center gap-3 border-r border-white/5 pr-4">
            <div className={cn(
              "h-1.5 w-1.5 rounded-full animate-pulse transition-all duration-500",
              isConnected ? "bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.4)]" : "bg-red-600 shadow-[0_0_10px_rgba(220,38,38,0.4)]"
            )} />
            <span className={cn(
              "text-[10px] font-black uppercase tracking-widest leading-none",
              isConnected ? "text-slate-100" : "text-red-500"
            )}>
              {isConnected ? "Node Connected" : "Connection Lost"}
            </span>
            {isConnected && (
              <span className="text-[9px] font-black text-emerald-500/80 uppercase ml-1">v3.42-Core</span>
            )}
          </div>
          
          <div className={cn(
            "flex items-center gap-2 px-2 py-0.5 rounded transition-colors duration-300",
            !isVerified && "bg-red-950/80 border border-red-500/50 animate-pulse shadow-[0_0_15px_rgba(220,38,38,0.6)]"
          )}>
            <div className={cn(
              "h-1.5 w-1.5 rounded-full",
              isVerified ? "bg-primary/40 border border-primary/20" : "bg-red-500 shadow-[0_0_8px_rgba(220,38,38,1)]"
            )} />
            <span className={cn(
              "text-[9px] font-bold uppercase tracking-widest leading-none",
              isVerified ? "text-slate-400" : "text-red-400"
            )}>
              {isVerified ? "Merkle Root:" : "🚨 ALERT:"}
            </span>
            <span className={cn(
              "text-[10px] font-black font-heading leading-none",
              isVerified ? "text-slate-100" : "text-red-500 animate-bounce"
            )}>
              {isVerified ? (merkleRoot ? merkleRoot.substring(0, 16) + "..." : "Syncing...") : "LEDGER COMPROMISED"}
            </span>
          </div>
        </div>

        <div className="h-6 w-px bg-white/10" />

        {/* Global Screen Shake Effect wrapper if compromised */}
        {!isVerified && (
          <div className="fixed inset-0 pointer-events-none z-[9999] border-[8px] border-red-600/50 animate-[pulse_1.5s_ease-in-out_infinite] shadow-[inset_0_0_150px_rgba(220,38,38,0.2)]" />
        )}

        <div className="flex items-center gap-6">
          <div className="text-right hidden md:block">
            <p className="text-[9px] font-bold text-slate-400 uppercase leading-none mb-1 tracking-[0.1em]">System Time</p>
            <p className="text-xs font-black font-heading text-slate-100 leading-none">{time}</p>
          </div>
          
          <div className="flex items-center gap-2">
            <button className="p-2 text-slate-500 hover:text-slate-100 transition-colors">
              <Search className="h-4 w-4" />
            </button>
            <button className="p-2 text-slate-500 hover:text-slate-100 transition-colors relative">
              <Bell className="h-4 w-4" />
              <div className="absolute top-1.5 right-1.5 h-2 w-2 bg-red-600 rounded-full border border-slate-950 shadow-sm" />
            </button>
            <button className="p-2 text-slate-500 hover:text-slate-100 transition-colors">
              <Terminal className="h-4 w-4" />
            </button>
          </div>

          <div className="h-9 w-9 rounded-sm bg-secondary border border-white/10 flex items-center justify-center font-black text-xs text-slate-100 shadow-lg tracking-tighter">
            MN
          </div>
        </div>
      </div>
    </header>
  );
}
