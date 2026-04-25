"use client";

import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, Clock, ShieldAlert, TrendingUp, Search, TrendingDown, Target } from "lucide-react";
import { MOCK_STATS } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

export function RiskHeader({ stats }: { stats?: any }) {
  const metrics = [
    { 
      label: "Total Events (Stream)", 
      value: stats?.total_processed?.toLocaleString() || "0", 
      status: "LIVE", 
      statusColor: "bg-emerald-900/10 text-emerald-500", 
      icon: Search,
      color: "text-slate-500",
      glow: "after:absolute after:inset-0 after:bg-primary/5 after:blur-xl"
    },
    { 
      label: "Speed (Logs/sec)", 
      value: stats?.throughput_lps?.toFixed(1) ? stats.throughput_lps.toFixed(1) + " lps" : "0.0 lps", 
      status: "OPTIMAL", 
      statusColor: "bg-emerald-900/10 text-emerald-500", 
      icon: Clock,
      color: "text-slate-500",
      glow: "after:absolute after:inset-0 after:bg-primary/5 after:blur-xl"
    },
    { 
      label: "Active High-Risk", 
      value: stats?.alert_count?.toLocaleString() || "0", 
      status: "WATCHING", 
      statusColor: "bg-slate-900/40 text-slate-500", 
      icon: ShieldAlert,
      color: "text-red-900/60",
      border: "border-l-2 border-l-red-900/40"
    },
    { 
      label: "System Risk Score", 
      value: stats?.highest_risk_score || "0", 
      status: "CALCULATING", 
      statusColor: "bg-emerald-900/10 text-emerald-500", 
      icon: Target,
      color: "text-slate-500",
      glow: "after:absolute after:inset-0 after:bg-primary/5 after:blur-xl"
    },
  ];

  return (
    <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
      {metrics.map((m, idx) => (
        <Card 
          key={idx} 
          className={cn(
            "relative bg-[#141A23] border-none rounded-none p-6 flex flex-col justify-between group hover:bg-[#1E293B]/40 transition-all overflow-hidden",
            m.border
          )}
        >
          <div className="flex justify-between items-start mb-4 relative z-10">
            <m.icon className={cn("h-5 w-5", m.color)} />
          </div>
          <div className="relative z-10 flex flex-col justify-between h-full">
            <div>
              <p className="text-[10px] font-bold font-heading uppercase tracking-[0.2em] text-slate-500 group-hover:text-slate-400 transition-colors">
                {m.label}
              </p>
              <h3 className="text-4xl font-black font-heading mt-2 tracking-tighter text-slate-100">
                {m.value}
              </h3>
            </div>
            <div className="flex items-center gap-2 mt-4">
              <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded-sm uppercase tracking-widest", m.statusColor)}>
                {m.status}
              </span>
              <span className="text-[9px] text-slate-600 font-medium">Session Sync</span>
            </div>
          </div>
          <div className={cn("absolute inset-0 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity", m.glow)} />
        </Card>
      ))}
    </section>
  );
}
