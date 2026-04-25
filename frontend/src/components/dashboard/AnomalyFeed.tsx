import { useRef, useEffect } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { MOCK_ANOMALIES, Anomaly } from "@/lib/mock-data";
import { motion } from "framer-motion";
import { AlertCircle, User, Zap } from "lucide-react";
import { cn } from "@/lib/utils";

interface AnomalyFeedProps {
  onSelectAnomaly: (anomaly: any) => void;
  selectedId?: string;
  anomalies: any[];
}

export function AnomalyFeed({ onSelectAnomaly, selectedId, anomalies }: AnomalyFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll disabled to allow manual exploration
  // Users can freely scroll up and down without being dragged.

  return (
    <div className="flex flex-col h-full bg-[#0A0E14] border border-white/[0.03] rounded-sm overflow-hidden transition-all duration-500">
      <div className="p-4 border-b border-white/[0.03] flex items-center justify-between bg-white/[0.01]">
        <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] flex items-center gap-2 text-slate-400">
          <Zap className="h-4 w-4 text-primary" />
          Live Anomaly Feed
        </h3>
        <button className="text-[9px] uppercase font-bold text-slate-600 hover:text-slate-400 transition-colors tracking-widest flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          Streaming
        </button>
      </div>
      
      <ScrollArea className="flex-1">
        <div className="p-2 space-y-2">
          {anomalies.map((anomaly, idx) => (
            <motion.div
              key={anomaly.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: idx * 0.05 }}
              onClick={() => onSelectAnomaly(anomaly)}
              className={cn(
                "p-4 rounded-sm border cursor-pointer transition-all duration-300 group relative overflow-hidden",
                selectedId === anomaly.id 
                  ? "bg-[#141A23] border-primary/20" 
                  : "bg-black/20 border-white/[0.03] hover:border-white/10"
              )}
            >
              {/* Severity Indicator Bar */}
              <div 
                className={cn(
                  "absolute left-0 top-0 bottom-0 w-1 transition-all",
                  (anomaly.riskScore > 85) ? "bg-red-800" :
                  (anomaly.riskScore > 30) ? "bg-orange-800" :
                  "bg-emerald-900/60"
                )}
              />

              <div className="flex justify-between items-start mb-2">
                <div className="flex items-center gap-2">
                  <User className="h-3 w-3 text-slate-600" />
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tighter">
                    {anomaly.user}
                  </span>
                </div>
                <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">
                  {new Date(anomaly.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>

              <div className="mb-3">
                <p className="text-xs text-slate-200 font-medium line-clamp-1">
                  Access: {anomaly.description || "System Resource"}
                </p>
              </div>

              <div className="flex items-center justify-between">
                <Badge 
                  className={cn(
                    "text-[8px] py-0.5 px-2 font-bold uppercase tracking-widest border-none rounded-sm bg-white/5 text-slate-400"
                  )}
                >
                  {anomaly.type}
                </Badge>
                <div className="flex items-center gap-2">
                  <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Risk Score:</span>
                  <span className={cn(
                    "text-xs font-black font-heading tracking-tighter",
                    (anomaly.riskScore > 85) ? "text-red-500" : "text-slate-100"
                  )}>
                    {anomaly.riskScore}
                  </span>
                </div>
              </div>
            </motion.div>
          ))}
          {/* Scroll Anchor */}
          <div ref={scrollRef} />
        </div>
      </ScrollArea>
    </div>
  );
}
