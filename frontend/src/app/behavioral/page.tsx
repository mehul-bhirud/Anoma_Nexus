"use client";

import { useState } from "react";
import { XaiPanel } from "@/components/dashboard/XaiPanel";
import { Anomaly } from "@/lib/mock-data";
import { 
  User, 
  Search, 
  Filter, 
  BrainCircuit, 
  Activity, 
  Clock, 
  AlertTriangle,
  Zap,
  CheckCircle2
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider
} from "@/components/ui/tooltip";
import { ScrollArea } from "@/components/ui/scroll-area";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

import { useAegisStream } from "@/hooks/use-aegis-stream";
import { ThreatModal } from "@/components/dashboard/ThreatModal";

export default function BehavioralPage() {
  const { anomalies } = useAegisStream();
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [isThreatModalOpen, setIsThreatModalOpen] = useState(false);

  const fallbackAnomaly: Anomaly = {
    id: "fallback",
    user: "Awaiting Sync...",
    type: "Standby",
    severity: "Low",
    timestamp: new Date().toISOString(),
    description: "",
    reconstructionLoss: 0,
    riskScore: 0,
    aiSummary: "",
    location: "",
    hourlyActivity: Array(24).fill(0)
  };
  const selectedUser = anomalies.find(a => a.id === selectedUserId) || anomalies[0] || fallbackAnomaly;

  const handleEntitySelect = (u: Anomaly) => {
    setSelectedUserId(u.id);
    if (u.severity === 'Critical') {
      setIsThreatModalOpen(true);
    }
  };

  return (
    <>
      <ThreatModal 
        threat={selectedUser}
        isOpen={isThreatModalOpen}
        onClose={() => setIsThreatModalOpen(false)}
        onAction={(action) => {
          console.log(`Action: ${action} on ${selectedUser.user}`);
          setIsThreatModalOpen(false);
        }}
      />
      <div className="grid grid-cols-12 gap-8 h-[calc(100vh-140px)]">
      {/* Left Sidebar: Investigation Triage */}
      <aside className="col-span-12 lg:col-span-3 flex flex-col gap-4">
        <div className="bg-[#0A0E14] p-4 flex flex-col h-full border border-white/[0.03]">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-[10px] font-black font-heading uppercase tracking-[0.2em] text-slate-500">Active Investigations</h2>
            <Filter className="h-4 w-4 text-slate-600" />
          </div>
          
          <ScrollArea className="flex-1">
            <div className="flex flex-col gap-2">
              {anomalies.map((u) => (
                <div 
                  key={u.id}
                  onClick={() => handleEntitySelect(u)}
                  className={cn(
                    "p-4 transition-all duration-300 cursor-pointer border-l-2 relative group rounded-sm",
                    selectedUser.id === u.id 
                      ? "bg-[#141A23] border-l-primary/40 shadow-xl" 
                      : "bg-transparent border-l-transparent hover:bg-white/[0.02] hover:border-l-white/10"
                  )}
                >
                  <div className="flex items-center gap-3">
                    <div className={cn(
                      "w-10 h-10 flex items-center justify-center rounded-sm transition-colors",
                      selectedUser.id === u.id ? "bg-primary/20" : "bg-white/[0.02]"
                    )}>
                      <User className={cn("h-5 w-5", selectedUser.id === u.id ? "text-primary" : "text-slate-600")} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-black text-slate-100 truncate tracking-tight">{u.user}</div>
                      <div className="text-[9px] text-slate-400 font-bold uppercase tracking-widest">{u.type}</div>
                    </div>
                    <div className="text-right">
                      <div className={cn(
                        "text-sm font-black font-heading tracking-tighter",
                        u.severity === 'Critical' ? "text-red-500" : "text-orange-500"
                      )}>{Math.round(u.reconstructionLoss * 100)}%</div>
                      <div className="text-[8px] text-slate-600 font-black uppercase tracking-widest">RISK</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      </aside>

      {/* Main Analysis Workspace */}
      <main className="col-span-12 lg:col-span-9 h-full">
        <ScrollArea className="h-full pr-4">
          <div className="flex flex-col gap-6 pb-6 pt-2">
            {/* Top: Temporal Rhythm & Sentiment */}
            <div className="bg-card/50 p-8 pt-12 border border-slate-800/50 rounded-sm shadow-sm relative group/chart min-h-[300px] backdrop-blur-md">
              <div className="flex items-center justify-between mb-10">
                <div>
                  <h2 className="text-2xl font-black font-heading uppercase tracking-tight text-slate-100 leading-none">Temporal Rhythm Analysis</h2>
                  <p className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.2em] mt-3">24-Hour activity mapping vs Network Baseline</p>
                </div>
                <div className="flex items-center gap-6">
               <LegendItem color="bg-slate-800/40 border border-slate-700/50" label="Normal" />
               <LegendItem color="bg-primary/20 border border-primary/30" label="Active" />
               <LegendItem color="bg-red-500/10 border border-red-500/30" label="Anomaly" />
            </div>
          </div>
          
          <div className="grid grid-cols-24 gap-3 h-32 mt-6">
            <TooltipProvider delay={0}>
              {selectedUser.hourlyActivity.map((score, i) => (
                <Tooltip key={i}>
                  <TooltipTrigger>
                    <div className="flex flex-col items-center justify-end h-full pb-3 cursor-crosshair group/bar">
                      <span className={cn(
                        "text-[8px] font-black mb-2 transition-all opacity-40 group-hover/bar:opacity-100",
                        score > 80 ? "text-red-500" : 
                        score > 40 ? "text-primary" : "text-slate-600"
                      )}>
                        {score}%
                      </span>
                      <motion.div 
                        layout
                        initial={{ height: 0 }}
                        animate={{ 
                          height: `${Math.max(score, 8)}%`,
                          background: score > 80 ? "linear-gradient(to top, rgba(225, 29, 72, 0.4), rgba(225, 29, 72, 0.05))" : 
                                      score > 40 ? "linear-gradient(to top, rgba(56, 189, 248, 0.3), rgba(56, 189, 248, 0.05))" : "rgba(148, 163, 184, 0.03)"
                        }}
                        className={cn(
                          "w-full rounded-[1px] transition-all border-x border-t",
                          score > 80 ? "border-red-500/40" : 
                          score > 40 ? "border-primary/30" : "border-slate-800/40"
                        )}
                      />
                    </div>
                  </TooltipTrigger>
                  <TooltipContent side="top" className="!bg-slate-100 !text-slate-950 px-3 py-2 border-none shadow-2xl rounded-sm">
                    <div className="flex flex-col gap-1">
                      <span className="text-[10px] font-black uppercase tracking-widest text-slate-500">{i.toString().padStart(2, '0')}:00h Analysis</span>
                      <div className="flex items-center gap-2">
                        <span className={cn("text-lg font-black font-heading tracking-tighter", score > 80 ? "text-red-600" : "text-slate-900")}>{score}%</span>
                        <span className="text-[8px] font-black uppercase text-slate-400">Risk Variance</span>
                      </div>
                    </div>
                  </TooltipContent>
                </Tooltip>
              ))}
            </TooltipProvider>
          </div>
          <div className="flex justify-between mt-4 text-[10px] font-black text-slate-600 uppercase tracking-[0.3em]">
             <span>00h</span>
             <span>04h</span>
             <span>08h</span>
             <span>12h</span>
             <span>16h</span>
             <span>20h</span>
             <span>23h</span>
          </div>
        </div>

        {/* Middle: Bento Grid of Specific Indicators */}
        <div className="grid grid-cols-2 gap-6">
          {/* Dynamic Telemetry Context */}
          <div className="bg-[#0A0E14] p-6 border-l-4 border-l-red-900/60 shadow-lg">
            <div className="flex items-center gap-3 mb-8">
               <Activity className="h-5 w-5 text-red-500" />
               <h2 className="text-lg font-black font-heading uppercase tracking-tight text-slate-100">Telemetry Context</h2>
            </div>
            <div className="grid grid-cols-2 gap-4 mb-8">
               <MetricSquare label="Risk Score" value={selectedUser.riskScore} sub="System Assigned" danger={selectedUser.riskScore > 80} />
               <MetricSquare label="Deviance" value={`${Math.round(selectedUser.reconstructionLoss * 100)}%`} sub="Neural Loss Rate" warning={selectedUser.reconstructionLoss > 0.5} />
            </div>
            <div className="space-y-4">
               <LogEntry 
                  title={selectedUser.type} 
                  desc={selectedUser.description || "Telemetry signature active"} 
                  type={selectedUser.severity === 'Critical' ? "critical" : "muted"} 
               />
            </div>
          </div>

          {/* Feature Importance (Reused XAI Component) */}
          <XaiPanel anomaly={selectedUser} />
        </div>

        {/* Bottom: AI Narrative */}
        <div className="bg-[#0A0E14] p-8 border border-white/[0.03] shadow-xl">
           <h2 className="text-lg font-black font-heading mb-6 flex items-center gap-3 text-slate-100">
             <BrainCircuit className="h-5 w-5 text-primary" />
             Investigative Narrative (AI-Generated)
           </h2>
           <div className="flex gap-6">
              <div className="h-12 w-12 shrink-0 rounded-sm bg-primary/10 flex items-center justify-center border border-primary/20">
                 <Zap className="h-6 w-6 text-primary" />
              </div>
              <div className="space-y-6">
                <p className="text-base leading-relaxed text-slate-300 font-medium">
                  {selectedUser.aiSummary ? (
                    selectedUser.aiSummary
                  ) : (
                    <span className="opacity-50 italic">Awaiting neural analysis from the Sentinel node...</span>
                  )}
                </p>
                <div className="flex gap-4">
                   <ActionButton label="Freeze Credentials" primary />
                   <ActionButton label="Flag for Review" />
                   <ActionButton label="Open Log Stream" />
                </div>
              </div>
           </div>
        </div>
          </div>
        </ScrollArea>
      </main>
    </div>
  </>
  );
}

function LegendItem({ color, label }: { color: string, label: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className={cn("h-3 w-3 rounded-sm", color)} />
      <span className="text-[10px] text-slate-400 uppercase font-black tracking-widest">{label}</span>
    </div>
  );
}

function MetricSquare({ label, value, sub, danger, warning }: any) {
  return (
    <div className="bg-[#141A23] p-4 rounded-sm border border-white/5 transition-all hover:border-white/10 shadow-sm">
      <div className="text-[9px] text-slate-500 font-black uppercase tracking-widest mb-1.5">{label}</div>
      <div className={cn("text-3xl font-black font-heading tracking-tighter", danger ? "text-red-500" : "text-slate-100")}>{value}</div>
      <div className={cn("text-[9px] uppercase font-black tracking-widest mt-1", danger ? "text-red-900/60" : "text-slate-500")}>{sub}</div>
    </div>
  );
}

function LogEntry({ title, desc, type }: any) {
  return (
    <div className="flex items-center gap-4 group">
      <div className={cn("w-1 h-10 rounded-full transition-all group-hover:w-1.5", type === 'critical' ? "bg-red-500" : "bg-white/10")} />
      <div>
        <div className="text-sm font-black text-slate-200 group-hover:text-white transition-colors tracking-tight">{title}</div>
        <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mt-0.5">{desc}</div>
      </div>
    </div>
  );
}

function ActionButton({ label, primary }: { label: string, primary?: boolean }) {
  return (
    <button className={cn(
      "px-5 py-2 text-[10px] font-black uppercase tracking-[0.2em] transition-all border rounded-sm",
      primary 
        ? "bg-primary/10 border-primary/40 text-primary hover:bg-primary/20 shadow-md" 
        : "border-white/10 text-slate-400 hover:text-white hover:bg-white/5"
    )}>
      {label}
    </button>
  );
}
