"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Shield, ShieldAlert, Link2, Unlink } from "lucide-react";
import { cn } from "@/lib/utils";
import { useMemo } from "react";

// ── Types ────────────────────────────────────────────────────────────────

interface LedgerBlock {
  hash: string;
  prevHash: string;
  action: string;
  user: string;
  timestamp: string;
  sequence: number;
  integrity: "Verified" | "COMPROMISED";
}

interface LedgerVisualizerProps {
  logs: any[];
  merkleRoot: string;
  isIntegrityVerified: boolean;
}

// ── Helpers ──────────────────────────────────────────────────────────────

function extractHash(log: any): string {
  return log?.merkle_root || log?.aegis_analysis?.merkle_root || "0x000…";
}

function synthPrevHash(hash: string): string {
  // Reverse and rotate to simulate a plausible previous root
  if (!hash || hash.length < 8) return "0x000…";
  const chars = hash.replace("…", "").split("");
  chars.reverse();
  return chars.slice(0, 12).join("") + "…";
}

// ═══════════════════════════════════════════════════════════════════════════
//  COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export function LedgerVisualizer({ logs, merkleRoot, isIntegrityVerified }: LedgerVisualizerProps) {
  const blocks: LedgerBlock[] = useMemo(() => {
    const recent = logs.slice(-5);
    return recent.map((log, idx) => {
      const hash = extractHash(log);
      const prevLog = idx > 0 ? recent[idx - 1] : null;
      const prevHash = prevLog ? extractHash(prevLog) : "AEGIS_GENESIS";
      const isTampered = !isIntegrityVerified || log?.merkle_integrity === "COMPROMISED";

      return {
        hash,
        prevHash,
        action: log?.type || log?.raw_log?.action?.type || "telemetry_event",
        user: log?.user || log?.raw_log?.actor?.user?.uid || "???",
        timestamp: log?.timestamp || "",
        sequence: log?.sequence || idx,
        integrity: isTampered ? "COMPROMISED" : "Verified",
      };
    });
  }, [logs, isIntegrityVerified]);

  const chainBroken = !isIntegrityVerified;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] flex items-center gap-3 text-slate-400">
          <span className="w-1.5 h-6 bg-primary" />
          Cryptographic Integrity Ledger
        </h3>
        <div className={cn(
          "flex items-center gap-2 px-2.5 py-1 rounded-sm border text-[9px] font-black font-mono uppercase tracking-wider transition-all",
          chainBroken
            ? "border-red-500/40 bg-red-950/30 text-red-400 animate-pulse"
            : "border-emerald-500/20 bg-emerald-950/20 text-emerald-400"
        )}>
          {chainBroken ? <ShieldAlert className="h-3 w-3" /> : <Shield className="h-3 w-3" />}
          {chainBroken ? "CHAIN COMPROMISED" : "CHAIN VERIFIED"}
        </div>
      </div>

      {/* Live Root Display */}
      <div className={cn(
        "px-4 py-3 rounded-sm border font-mono text-xs transition-all",
        chainBroken
          ? "border-red-500/30 bg-red-950/20"
          : "border-white/5 bg-white/[0.02]"
      )}>
        <span className="text-slate-500 text-[10px] uppercase tracking-widest font-bold mr-3">Live Root</span>
        <span className={cn(
          "font-bold",
          chainBroken ? "text-red-400" : "text-emerald-400"
        )}>
          {merkleRoot || "Awaiting first block…"}
        </span>
      </div>

      {/* Chain Visualization */}
      <div className="relative">
        <AnimatePresence mode="popLayout">
          {blocks.length === 0 && (
            <div className="text-center py-10 text-slate-600 text-xs font-mono">
              Awaiting telemetry stream to build chain…
            </div>
          )}

          {blocks.map((block, idx) => {
            const isBroken = block.integrity === "COMPROMISED";
            const isLast = idx === blocks.length - 1;

            return (
              <motion.div
                key={`${block.sequence}-${block.hash}`}
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.3, delay: idx * 0.05 }}
              >
                {/* Block */}
                <div className={cn(
                  "relative border rounded-sm px-4 py-3 font-mono text-[11px] transition-all",
                  isBroken
                    ? "border-red-500/40 bg-red-950/20 shadow-[0_0_20px_rgba(239,68,68,0.08)]"
                    : "border-white/5 bg-white/[0.02] hover:border-white/10 hover:bg-white/[0.04]"
                )}>
                  {/* Block Number Badge */}
                  <div className="absolute -top-2 -left-1.5">
                    <span className={cn(
                      "text-[8px] font-black px-1.5 py-0.5 rounded-sm uppercase tracking-wider",
                      isBroken
                        ? "bg-red-500 text-white"
                        : "bg-slate-800 text-slate-400 border border-white/5"
                    )}>
                      #{block.sequence}
                    </span>
                  </div>

                  <div className="space-y-1.5 mt-1">
                    {/* Previous Hash */}
                    <div className="flex items-center gap-2">
                      <span className="text-slate-600 w-10 shrink-0">Prev</span>
                      <span className={cn(
                        "truncate",
                        isBroken ? "text-red-500/60 line-through" : "text-slate-500"
                      )}>
                        {block.prevHash}
                      </span>
                    </div>

                    {/* Action */}
                    <div className="flex items-center gap-2">
                      <span className="text-emerald-600 w-10 shrink-0">+Add</span>
                      <span className="text-slate-300 font-bold">
                        {block.action}
                      </span>
                      <span className="text-slate-600 text-[9px]">
                        by {block.user}
                      </span>
                    </div>

                    {/* New Root */}
                    <div className="flex items-center gap-2">
                      <span className={cn(
                        "w-10 shrink-0 font-bold",
                        isBroken ? "text-red-500" : "text-cyan-500"
                      )}>Root</span>
                      <span className={cn(
                        "font-bold tracking-wide",
                        isBroken ? "text-red-400" : "text-cyan-400"
                      )}>
                        {block.hash}
                      </span>
                      {isBroken && (
                        <span className="text-[8px] text-red-500 font-black uppercase tracking-widest animate-pulse ml-auto">
                          TAMPERED
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Chain Connector */}
                {!isLast && (
                  <div className="flex flex-col items-center py-1.5">
                    <div className={cn(
                      "w-px h-3",
                      isBroken ? "bg-red-500/50" : "bg-white/10"
                    )} />
                    {isBroken ? (
                      <Unlink className="h-3.5 w-3.5 text-red-500 animate-pulse my-0.5" />
                    ) : (
                      <Link2 className="h-3.5 w-3.5 text-slate-600 my-0.5" />
                    )}
                    <div className={cn(
                      "w-px h-3",
                      isBroken ? "bg-red-500/50" : "bg-white/10"
                    )} />
                  </div>
                )}
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </div>
  );
}
