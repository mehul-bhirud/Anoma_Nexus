"use client";

import { RiskHeader } from "@/components/dashboard/RiskHeader";
import { AnomalyFeed } from "@/components/dashboard/AnomalyFeed";
import { Anomaly } from "@/lib/mock-data";
import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Download, Users, Briefcase, Activity as ActivityIcon } from "lucide-react";
import { motion } from "framer-motion";
import { ThreatModal } from "@/components/dashboard/ThreatModal";
import { LedgerVisualizer } from "@/components/dashboard/LedgerVisualizer";
import { cn } from "@/lib/utils";
import { useAegisStream } from "@/hooks/use-aegis-stream";

export default function OverviewPage() {
  const { anomalies, connectionStatus, backendStats, merkleRoot, isIntegrityVerified } = useAegisStream();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);
  
  const latestLog = anomalies.length > 0 ? anomalies[anomalies.length - 1] : null;
  const displayRoot = latestLog?.merkle_root ?? latestLog?.aegis_analysis?.merkle_root ?? "Syncing...";
  const displayTime = mounted && latestLog?.timestamp 
      ? new Date(latestLog.timestamp).toLocaleTimeString() 
      : "00:00:00";

  const [selectedAnomaly, setSelectedAnomaly] = useState<any | null>(null);
  const [isThreatModalOpen, setIsThreatModalOpen] = useState(false);

  // Monitor incoming stream for Kill Screen trigger (Disabled based on feedback)
  useEffect(() => {
    if (anomalies.length > 0) {
      const latestAnomaly = anomalies[0];
      if (latestAnomaly?.riskScore > 85 || latestAnomaly?.aegis_analysis?.risk_score > 85) {
        setSelectedAnomaly(latestAnomaly);
        // setIsThreatModalOpen(true); -> Disabled popup
      }
    }
  }, [anomalies]);

  const dynamicUsers = [...anomalies]
    .filter((v, i, a) => a.findIndex(t => t.user === v.user) === i) // Unique
    .sort((a, b) => b.riskScore - a.riskScore) // Highest risk first
    .map(a => ({
      id: a.user,
      name: a.user,
      dept: a.location || "System Access",
      status: a.riskScore > 85 ? "SUSPICIOUS" : a.riskScore > 50 ? "WATCHLIST" : "CLEARED",
      score: a.riskScore,
      avatar: a.user ? a.user.substring(0, 2).toUpperCase() : "?",
      color: a.riskScore > 85 ? "text-red-500" : a.riskScore > 50 ? "text-orange-500" : "text-emerald-500",
      raw: a
    }))
    .slice(0, 5);
  
  const leaderboard = dynamicUsers;

  const handleSelectAnomaly = (anomaly: any) => {
    setSelectedAnomaly(anomaly);
    if (anomaly?.aegis_analysis?.risk_score > 85) {
      setIsThreatModalOpen(true);
    }
  };

  const handleLeaderboardClick = (user: any) => {
     if (user.raw) {
        setSelectedAnomaly(user.raw);
        setIsThreatModalOpen(true);
     } else if (user.status === "SUSPICIOUS") {
        const anomaly = anomalies.find((a: any) => a.user.includes(user.avatar.toLowerCase())) || anomalies[0];
        setSelectedAnomaly(anomaly);
        setIsThreatModalOpen(true);
     }
  };

  return (
    <>
      <ThreatModal 
        threat={selectedAnomaly}
        isOpen={isThreatModalOpen}
        onClose={() => setIsThreatModalOpen(false)}
        onAction={(action) => {
          console.log(`Command Executed: ${action} for ${selectedAnomaly?.user}`);
          setIsThreatModalOpen(false);
        }}
      />
      
      <div className="space-y-10">
        {/* Page Header */}
        <header className="flex justify-between items-end border-b border-white/5 pb-6">
          <div>
            <p className="text-[10px] font-heading font-bold uppercase tracking-[0.2em] text-slate-500 mb-1">Command Center</p>
            <h2 className="text-3xl font-extrabold font-heading tracking-tight text-slate-100">Executive Overview</h2>
          </div>
          <div className="flex items-center gap-4">
            <button className="px-4 py-2 text-[10px] font-bold font-heading border border-white/5 hover:bg-white/5 transition-all text-slate-300 uppercase tracking-widest flex items-center gap-2">
              <Download className="h-3 w-3" /> Generate Report
            </button>
            <div className="w-px h-6 bg-white/5"></div>
            <span className="text-[10px] font-mono text-emerald-500 bg-emerald-900/10 border border-emerald-500/20 px-2 py-1 rounded">
              VERIFIED: {displayRoot.toString().slice(0, 12)}
            </span>
            <p className="text-[10px] font-mono text-muted-foreground/60 bg-white/5 px-2 py-1 rounded">
              {connectionStatus ? "LIVE" : "DISCONNECTED"}
            </p>
            <p className="text-[10px] font-mono text-muted-foreground/60 bg-white/5 px-2 py-1 rounded">
              {displayTime}
            </p>
          </div>
        </header>

        {/* KPI Grid */}
        <RiskHeader stats={backendStats} />

        {/* Main Grid */}
        <div className="grid grid-cols-12 gap-8">
          {/* User Leaderboard */}
          <div className="col-span-12 lg:col-span-8 space-y-6">
            <div className="flex items-center justify-between">
               <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] flex items-center gap-3 text-slate-400">
                 <span className="w-1.5 h-6 bg-primary" />
                 Entity Risk Attribution Ranking
               </h3>
               <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600">Real-time Analysis</span>
            </div>

            <div className="glass-panel overflow-hidden border border-white/5 bg-card/40">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-white/[0.01] text-[10px] uppercase tracking-widest text-slate-500 font-bold border-b border-white/5">
                    <th className="px-6 py-4">User Identity</th>
                    <th className="px-6 py-4">Department</th>
                    <th className="px-6 py-4">Status</th>
                    <th className="px-6 py-4 text-right">Risk Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.02]">
                  {leaderboard.map((user, idx) => (
                    <motion.tr 
                      key={user.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.05 }}
                      onClick={() => handleLeaderboardClick(user)}
                      className={cn(
                        "group transition-colors cursor-pointer",
                        user.status === "SUSPICIOUS" ? "hover:bg-red-950/20" : "hover:bg-slate-800/40"
                      )}
                    >
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className={cn(
                            "w-9 h-9 rounded-sm flex items-center justify-center border font-bold text-xs transition-colors",
                            user.status === 'SUSPICIOUS' ? "bg-red-950/30 border-red-500/30 text-red-500" : "bg-secondary border-white/5 text-slate-400"
                          )}>
                            {user.avatar}
                          </div>
                          <div>
                            <p className={cn(
                              "text-sm font-bold transition-colors",
                              user.status === 'SUSPICIOUS' ? "text-red-400" : "text-slate-200 group-hover:text-primary"
                            )}>{user.id}</p>
                            <p className="text-[9px] text-slate-600 font-bold uppercase tracking-widest">Metadata Verified</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-xs font-medium text-slate-500">{user.dept}</td>
                      <td className="px-6 py-4">
                        <Badge variant="outline" className={cn(
                          "text-[9px] font-bold border-none px-2 py-0.5 rounded-sm",
                          user.status === 'SUSPICIOUS' ? "bg-red-900/40 text-red-500 shadow-[0_0_10px_rgba(239,68,68,0.2)]" : 
                          (user.status === 'WATCHLIST' || user.status === 'INVESTIGATING') ? "bg-orange-900/10 text-orange-500" : 
                          "bg-emerald-900/10 text-emerald-500"
                        )}>
                          {user.status}
                        </Badge>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <span className={cn("font-heading font-black text-xl tracking-tighter", 
                          user.status === 'SUSPICIOUS' ? "text-red-500" : 
                          user.status === 'WATCHLIST' ? "text-orange-500" : 
                          user.status === 'INVESTIGATING' ? "text-orange-500/80" : "text-slate-400")}>
                          {user.score}
                        </span>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Anomaly Feed + Ledger (Right) */}
          <div className="col-span-12 lg:col-span-4 space-y-8 min-h-[500px]">
             <AnomalyFeed onSelectAnomaly={handleSelectAnomaly} selectedId={selectedAnomaly?.id} anomalies={anomalies} />
             <LedgerVisualizer logs={anomalies} merkleRoot={merkleRoot} isIntegrityVerified={isIntegrityVerified} />
          </div>
        </div>
      </div>
    </>
  );
}
