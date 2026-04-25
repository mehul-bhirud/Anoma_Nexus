"use client";

import { motion, AnimatePresence } from "framer-motion";
import { X, ShieldAlert, Zap, Lock, RefreshCcw } from "lucide-react";
import { Anomaly } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

interface ThreatModalProps {
  threat: any | null;
  isOpen: boolean;
  onClose: () => void;
  onAction: (action: "revoke" | "dismiss") => void;
}

export function ThreatModal({ threat, isOpen, onClose, onAction }: ThreatModalProps) {
  if (!threat) return null;

  const isFinancialFraud = threat?.signature_name === "SUPPLY_CHAIN_FRAUD";
  const isBiometricHijack = threat?.signature_name === "BIOMETRIC_HIJACK";
  const isSpecialAlert = isFinancialFraud || isBiometricHijack;

  // Dynamic color scheme per threat class
  const borderColor = isBiometricHijack
    ? "border-purple-600 shadow-[0_0_100px_rgba(168,85,247,0.2)]"
    : isFinancialFraud
    ? "border-yellow-600 shadow-[0_0_100px_rgba(234,179,8,0.15)]"
    : "border-white/10";

  const headerBg = isBiometricHijack
    ? "border-purple-900/50 bg-purple-900/20"
    : isFinancialFraud
    ? "border-yellow-900/50 bg-yellow-900/20"
    : "border-white/5";

  const accentColor = isBiometricHijack
    ? "text-purple-400"
    : isFinancialFraud
    ? "text-yellow-500"
    : "text-red-500";

  const headerLabel = isBiometricHijack
    ? "👁️ PHYSICAL TERMINAL HIJACK"
    : isFinancialFraud
    ? "⚠️ FINANCIAL FRAUD INTERCEPT"
    : "AEGIS Intercept";

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 bg-black/90 backdrop-blur-xl"
          />

          <motion.div 
            initial={{ scale: 0.98, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.98, opacity: 0 }}
            className={cn(
              "relative w-full max-w-xl bg-[#020408] shadow-[0_0_100px_rgba(255,0,0,0.1)] border rounded-sm overflow-hidden",
              borderColor
            )}
          >
            {/* Minimal Security Header */}
            <div className={cn(
               "px-8 py-6 border-b flex items-center justify-between",
               headerBg
            )}>
              <div className="flex items-center gap-3">
                <ShieldAlert className={cn("h-5 w-5", isSpecialAlert ? `${accentColor} animate-pulse` : "text-red-500")} />
                <h2 className={cn("text-xs font-black uppercase tracking-[0.3em]", isSpecialAlert ? accentColor : "text-slate-100")}>
                  {headerLabel}
                </h2>
              </div>
              <span className="text-[9px] font-black font-mono text-slate-500 uppercase tracking-widest">Protocol L5</span>
            </div>

            <div className="p-8 space-y-10">
              {/* Core Metrics */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">Risk Magnitude</p>
                  <div className="flex items-baseline gap-1">
                    <span className={cn("text-6xl font-black font-heading tracking-tighter", isSpecialAlert ? accentColor : "text-red-500")}>
                      {Math.round(threat?.aegis_analysis?.risk_score || threat?.risk_score || 0)}
                    </span>
                    <span className="text-xl font-black text-red-900/40 font-heading"></span>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Entity ID</p>
                  <p className="text-2xl font-black font-heading text-slate-100 tracking-tight">
                     {threat?.raw_log?.actor?.user?.uid || threat?.actor?.user?.uid || threat?.actor?.user_id || "Unknown"}
                  </p>
                </div>
              </div>

              {/* Biometric Telemetry Readout — only for hijack alerts */}
              {isBiometricHijack && (
                <div className="bg-purple-950/50 p-4 rounded-sm border border-purple-500/30 font-mono text-xs space-y-1.5">
                  <p className="text-purple-300 font-black uppercase tracking-widest text-[10px] mb-3">Biometric Deviation Report</p>
                  <p className="text-purple-200">▶ EXPECTED CADENCE: <span className="text-emerald-400 font-bold">110ms</span></p>
                  <p className="text-purple-200">▶ CURRENT CADENCE: <span className="text-red-400 font-bold">{threat?.raw_log?.enrichments?.aegis_telemetry?.typing_cadence_ms || "???"}ms</span> <span className="text-red-500/70">(Hunt-and-Peck detected)</span></p>
                  <p className="text-purple-200">▶ MOUSE VELOCITY:  <span className="text-red-400 font-bold">{threat?.raw_log?.enrichments?.aegis_telemetry?.mouse_velocity || "???"}</span> <span className="text-red-500/70">(Erratic — 4.7× baseline)</span></p>
                </div>
              )}

              {/* Vector & Metadata */}
              <div className="grid grid-cols-2 gap-8 py-6 border-y border-white/5">
                <div>
                   <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Vector Type</p>
                   <p className="text-xs font-black text-red-600 uppercase tracking-widest">{threat.type}</p>
                </div>
                <div className="text-right">
                   <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Terminal Origin</p>
                   <p className="text-xs font-bold text-slate-400 font-mono italic">{threat.location || 'Mesh-Node-04'}</p>
                </div>
              </div>

              {/* Simple AI Insight */}
              <div className="space-y-3">
                 <div className="flex items-center gap-2">
                   <Zap className="h-3 w-3 text-primary" />
                   <h3 className="text-[10px] font-black uppercase tracking-widest text-slate-500">
                     {isBiometricHijack ? "AI Contextual Analysis" : "Forensic Narrative"}
                   </h3>
                 </div>
                 <p className="text-sm text-slate-300 leading-relaxed font-medium italic bg-white/[0.02] p-4 border border-white/[0.03] rounded-sm">
                   {threat?.ai_analysis?.summary || threat?.aegis_analysis?.llm_forensics || "Insufficient forensic context available or LLM skipped due to concurrency limits."}
                 </p>
              </div>

              {/* Clean Action Selection */}
              <div className="flex flex-col gap-3">
                <button 
                  onClick={() => onAction("revoke")}
                  className="w-full bg-red-600 hover:bg-red-700 text-white font-black font-heading uppercase tracking-[0.2em] text-[10px] py-4 transition-all active:scale-95 shadow-lg"
                >
                  <div className="flex items-center justify-center gap-2">
                    <Lock className="h-4 w-4" />
                    Authorize Revocation
                  </div>
                </button>
                <button 
                  onClick={() => onClose()}
                  className="w-full bg-transparent hover:bg-white/[0.03] text-slate-500 hover:text-white font-black font-heading uppercase tracking-[0.2em] text-[10px] py-4 transition-all"
                >
                  Dismiss as False Positive
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
