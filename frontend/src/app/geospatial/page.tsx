"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Globe, ShieldAlert, Cpu, Terminal, Zap, MoveRight, MapPin, Database, Store, Server } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { ThreatModal } from "@/components/dashboard/ThreatModal";
import { useState } from "react";
import { useAegisStream } from "@/hooks/use-aegis-stream";

export default function GeospatialPage() {
  const { anomalies } = useAegisStream();
  const [isThreatModalOpen, setIsThreatModalOpen] = useState(false);
  const selectedThreat = anomalies.length > 0 ? anomalies[anomalies.length - 1] : null;

  const infraNodes = [
    { name: "INV", load: [20, 40, 10, 30, 20, 50] },
    { name: "POS", load: [40, 30, 80, 20, 20, 10] },
    { name: "PAY", load: [10, 10, 20, 30, 10, 40] },
    { name: "CDN", load: [80, 10, 30, 40, 60, 20] },
  ];

  const trafficAnomalies = [
    { node: "Payroll-Node-04", delta: "+410% Vol", target: "142.250.190.46", icon: Terminal, color: "text-neon-red", progress: 85, status: "Critical" },
    { node: "Inventory-DB-Main", delta: "Stable", target: "AWS-East-Region", icon: Database, color: "text-neon-cyan", progress: 20, status: "Healthy" },
    { node: "POS-Registry-Global", delta: "Encrypted", target: "Peer Healthy", icon: Store, color: "text-neon-green", progress: 12, status: "Secure" },
  ];

  return (
    <>
      <ThreatModal 
        threat={selectedThreat}
        isOpen={isThreatModalOpen}
        onClose={() => setIsThreatModalOpen(false)}
        onAction={(action) => setIsThreatModalOpen(false)}
      />

      <div className="grid grid-cols-12 gap-8 h-[calc(100vh-140px)]">
        {/* Left: Map & HUD (8 cols) */}
        <section className="col-span-12 lg:col-span-8 relative bg-black/40 overflow-hidden border border-white/5 flex flex-col group/map">
          {/* World Map Background Simulation */}
          <div className="absolute inset-0 opacity-20 pointer-events-none overflow-hidden">
            <div className="absolute inset-0 bg-[radial-gradient(rgba(255,255,255,0.05)_1px,transparent_1px)] [background-size:40px_40px]" />
            <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.02)_1px,transparent_1px)] [background-size:120px_120px]" />
            <div className="absolute inset-0 bg-gradient-to-tr from-red-600/[0.03] via-transparent to-primary/[0.03]" />
          </div>

          <div className="absolute top-4 left-1/2 -translate-x-1/2 flex items-center gap-6 z-20 bg-black/60 border border-white/5 px-6 py-2 rounded-full backdrop-blur-md opacity-0 group-hover/map:opacity-100 transition-all duration-500">
             <div className="flex items-center gap-2">
                <span className="text-[10px] font-black font-mono text-slate-500">LAT:</span>
                <span className="text-[10px] font-black font-mono text-slate-100">34.0522 N</span>
             </div>
             <div className="w-px h-3 bg-white/10" />
             <div className="flex items-center gap-2">
                <span className="text-[10px] font-black font-mono text-slate-500">LONG:</span>
                <span className="text-[10px] font-black font-mono text-slate-100">118.2437 W</span>
             </div>
          </div>

          {/* HUD: Top Left Stats */}
          <div className="absolute top-6 left-6 flex flex-col gap-3 z-20">
            <div className="bg-[#0A0E14]/95 backdrop-blur-xl border-l-2 border-l-primary p-5 rounded-sm shadow-2xl border border-white/[0.05]">
              <div className="text-[9px] uppercase font-black tracking-[0.2em] text-slate-500 leading-none mb-2">Network Sessions</div>
              <div className="text-3xl font-black font-heading text-slate-100 tracking-tighter leading-none">12,842</div>
            </div>
            <div className="bg-red-950/20 backdrop-blur-xl border-l-2 border-l-red-600 p-5 rounded-sm shadow-2xl border border-red-900/10">
              <div className="text-[9px] uppercase font-black tracking-[0.2em] text-red-500/80 leading-none mb-2">Impossible Travel</div>
              <div className="text-3xl font-black font-heading text-red-500 tracking-tighter leading-none">04</div>
            </div>
          </div>

          {/* HUD: Top Right Alert */}
          <div className="absolute top-6 right-6 w-80 glass-panel p-6 rounded-sm border border-red-600/30 z-20 bg-[#0A0E14]/95 shadow-[0_0_40px_rgba(220,38,38,0.1)]">
            <div className="flex items-center gap-2 text-red-500 mb-4">
               <ShieldAlert className="h-5 w-5 animate-pulse" />
               <h3 className="text-[11px] font-black uppercase tracking-[0.25em]">Threat Intelligence</h3>
            </div>
            <div className="text-sm font-black font-heading mb-2 text-slate-100 uppercase tracking-tight">Active Hijack: node-8842</div>
            <p className="text-[11px] text-slate-400 leading-relaxed mb-6 font-medium">Session jump detected between <span className="text-slate-100 font-bold">Lagos</span> and <span className="text-slate-100 font-bold">Zürich</span>. Velocity delta exceeds human physiological constraints.</p>
            <button 
              onClick={() => setIsThreatModalOpen(true)}
              className="w-full py-3 bg-red-600 hover:bg-red-700 text-white text-[10px] font-black uppercase tracking-[0.15em] transition-all shadow-lg active:scale-95 flex items-center justify-center gap-2"
            >
              <Zap className="h-4 w-4" />
              Engage AEGIS Protocol
            </button>
          </div>

          {/* Map Drawing Area */}
          <div className="flex-1 flex items-center justify-center p-10 relative">
            <svg viewBox="0 0 800 500" className="w-full max-w-5xl h-auto">
               <defs>
                 <linearGradient id="arcGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                   <stop offset="0%" stopColor="#ef4444" stopOpacity="0" />
                   <stop offset="50%" stopColor="#ef4444" stopOpacity="0.8" />
                   <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
                 </linearGradient>
                 <filter id="glow">
                   <feGaussianBlur stdDeviation="2.5" result="coloredBlur"/>
                   <feMerge>
                     <feMergeNode in="coloredBlur"/>
                     <feMergeNode in="SourceGraphic"/>
                   </feMerge>
                 </filter>
               </defs>

               {/* Grid Neural Mesh Overlay */}
               <path d="M0,250 L800,250 M400,0 L400,500" stroke="white" strokeWidth="0.5" strokeOpacity="0.05" />

               {/* Critical Impossible Travel Arcs */}
               <motion.path 
                  d="M200,300 Q400,100 600,350" 
                  fill="none" 
                  stroke="url(#arcGradient)" 
                  strokeWidth="3" 
                  filter="url(#glow)"
                  strokeDasharray="1000"
                  initial={{ strokeDashoffset: 1000 }}
                  animate={{ strokeDashoffset: -1000 }}
                  transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
               />
               <circle cx="200" cy="300" r="4" fill="#ef4444" className="shadow-lg shadow-red-500/50" />
               <circle cx="600" cy="350" r="4" fill="#ef4444" />
               <motion.circle 
                  cx="600" cy="350" r="8" fill="none" stroke="#ef4444" strokeWidth="1"
                  animate={{ scale: [1, 2.5], opacity: [0.8, 0] }}
                  transition={{ duration: 2, repeat: Infinity }}
               />

               {/* Regular Flows */}
               <path 
                  d="M150,150 Q300,100 500,180" 
                  fill="none" 
                  stroke="#008DA8" 
                  strokeWidth="0.5" 
                  strokeOpacity="0.3"
                  strokeDasharray="4 4" 
               />
               <circle cx="150" cy="150" r="2" fill="#008DA8" className="opacity-40" />
               <circle cx="500" cy="180" r="2" fill="#008DA8" className="opacity-40" />
            </svg>
          </div>

          <div className="p-8 mt-auto flex gap-8 bg-black/40 border-t border-white/5 mx-6 mb-6 rounded-sm">
             <LegendItem color="bg-red-600 shadow-[0_0_10px_rgba(239,68,68,0.5)]" label="Impossible Velocity Breach" />
             <LegendItem color="bg-primary/40" label="Global Verified Traffic" />
             <LegendItem color="bg-slate-700" label="Dormant Endpoints" />
          </div>
        </section>

        {/* Right: Infrastructure & Heatmap (4 cols) */}
        <aside className="col-span-12 lg:col-span-4 flex flex-col gap-6">
          <div className="bg-[#0A0E14] p-6 border border-white/[0.03] flex flex-col gap-6">
            <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Regional Load Vectors</h4>
          
          <div className="grid grid-cols-4 gap-2">
            {infraNodes.map((node) => (
              <div key={node.name} className="flex flex-col gap-2">
                <div className="text-[8px] font-bold text-slate-700 text-center">{node.name}</div>
                <div className="flex flex-col gap-1">
                  {node.load.map((l, i) => (
                    <div 
                      key={i} 
                      className={cn(
                        "h-4 rounded-sm transition-all",
                        l > 70 ? "bg-red-900/60" :
                        l > 40 ? "bg-primary/40" :
                        "bg-primary/5"
                      )} 
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="flex justify-between items-center text-[9px] font-bold text-slate-700 uppercase tracking-widest mt-4">
             <span>Low Load</span>
             <div className="h-1 flex-1 mx-4 bg-gradient-to-r from-primary/10 via-primary/40 to-red-900/60" />
             <span>Congestion</span>
          </div>
        </div>

        {/* Traffic Anomalies Section */}
        <div className="bg-[#0A0E14] p-6 border border-white/[0.03] flex-1 flex flex-col overflow-hidden">
           <h4 className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-6">Traffic Anomalies</h4>
           <div className="space-y-6 flex-1 overflow-y-auto pr-2">
              {trafficAnomalies.map((a, i) => (
                <div key={i} className="flex items-start gap-4 group cursor-pointer hover:bg-white/[0.02] p-2 transition-colors">
                   <div className={cn("w-10 h-10 rounded-sm flex items-center justify-center border", a.status === 'Critical' ? "bg-red-950/20 border-red-900/30" : "bg-[#141A23] border-white/5")}>
                      <a.icon className={cn("h-5 w-5", a.status === 'Critical' ? "text-red-500" : "text-slate-500")} />
                   </div>
                   <div className="flex-1 min-w-0">
                      <div className="flex justify-between items-start mb-1">
                        <span className="text-xs font-bold text-slate-200 truncate">{a.node}</span>
                        <span className={cn("text-[10px] font-bold font-mono tracking-tighter", a.status === 'Critical' ? "text-red-500" : "text-slate-500")}>{a.delta}</span>
                      </div>
                      <p className="text-[10px] text-slate-600 font-bold uppercase tracking-widest truncate">Target: {a.target}</p>
                      <div className="w-full bg-white/5 h-1 mt-3 rounded-full overflow-hidden">
                         <div className={cn("h-full", a.status === 'Critical' ? "bg-red-800" : "bg-primary/40")} style={{ width: `${a.progress}%` }} />
                      </div>
                   </div>
                </div>
              ))}
           </div>
        </div>
      </aside>

      <style jsx global>{`
        @keyframes dash {
          to {
            stroke-dashoffset: -100;
          }
        }
      `}</style>
    </div>
  </>
);
}

function LegendItem({ color, label }: { color: string, label: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className={cn("h-3 w-3 rounded-full shadow-[0_0_8px_rgba(0,0,0,0.5)]", color)} />
      <span className="text-[10px] text-muted-foreground uppercase font-bold">{label}</span>
    </div>
  );
}
