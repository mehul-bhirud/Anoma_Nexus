"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Anomaly } from "@/lib/mock-data";
import { motion } from "framer-motion";
import { BrainCircuit, Info, Cpu } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

interface XaiPanelProps {
  anomaly: Anomaly | null;
}

// ── Human-readable display names for raw feature_meta keys ──────────────
const FRIENDLY_NAMES: Record<string, string> = {
  hour_sin_mean:             "Timing Pattern",
  hour_sin_std:              "Time Variance",
  hour_cos_mean:             "Daily Cycle",
  hour_cos_std:              "Cycle Variance",
  is_weekend:                "Weekend Activity",
  is_out_of_hours:           "After-Hours",
  session_duration_s:        "Session Duration",
  log_count:                 "Event Volume",
  delta_s_mean:              "Avg Interval",
  delta_s_std:               "Interval Variance",
  delta_s_min:               "Min Interval",
  delta_s_max:               "Max Interval",
  velocity_lps:              "Action Velocity",
  volume_mb_sum:             "Total Data Vol",
  volume_mb_max:             "Max File Size",
  volume_mb_mean:            "Avg File Size",
  act_login_mean:            "Login Frequency",
  act_vpn_connect_mean:      "VPN Usage",
  act_db_query_mean:         "DB Queries",
  act_file_download_mean:    "File Downloads",
  act_file_copy_mean:        "File Copies",
  act_config_change_mean:    "Config Changes",
  act_usb_mount_mean:        "USB Activity",
  act_mfa_enroll_mean:       "MFA Enrollments",
  act_record_delete_mean:    "Record Deletion",
  act_permission_change_mean:"Permission Changes",
  act_process_kill_mean:     "Process Kills",
  typing_var_mean:           "Typing Cadence",
  typing_var_max:            "Typing Variance",
  file_entropy_max:          "File Entropy",
  file_entropy_mean:         "Avg Entropy",
  optical_det_mean:          "Optical Sensor",
  edr_off_mean:              "EDR Disabled",
  action_failed_mean:        "Failed Actions",
  flag_honey_token_max:      "Honey Token",
  flag_destructive_action_max: "Destructive Act",
  flag_critical_resource_max:  "Critical Resource",
  flag_optical_sensor_max:   "Camera Detected",
  flag_high_entropy_max:     "High Entropy",
  impossible_travel_max:     "Impossible Travel",
  mfa_success_mean:          "MFA Success",
  mfa_failed_mean:           "MFA Failures",
  mfa_bypassed_mean:         "MFA Bypassed",
};

function getFriendlyName(raw: string): string {
  return FRIENDLY_NAMES[raw] || raw.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

// ── Gradient color based on normalized intensity ────────────────────────
function getBarColor(pct: number): string {
  if (pct > 80) return "bg-red-500 shadow-[0_0_12px_rgba(239,68,68,0.4)]";
  if (pct > 50) return "bg-orange-500 shadow-[0_0_10px_rgba(249,115,22,0.3)]";
  if (pct > 25) return "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.25)]";
  return "bg-yellow-500/80";
}

function getBarTextColor(pct: number): string {
  if (pct > 80) return "text-red-400";
  if (pct > 50) return "text-orange-400";
  if (pct > 25) return "text-amber-400";
  return "text-yellow-400";
}

export function XaiPanel({ anomaly }: XaiPanelProps) {
  if (!anomaly) {
    return (
      <Card className="h-full border-dashed border-white/10 bg-transparent flex items-center justify-center">
        <div className="text-center p-6">
          <BrainCircuit className="h-10 w-10 text-muted-foreground/20 mx-auto mb-4" />
          <p className="text-sm text-muted-foreground font-mono">Select an anomaly to view XAI analysis</p>
        </div>
      </Card>
    );
  }

  // ── Use REAL xai_top_features from the backend (via WebSocket) ──────
  const features = anomaly.xai_top_features ?? [];
  const hasRealData = features.length > 0;

  // Normalize errors: the highest error gets 100% bar width
  const maxError = Math.max(...features.map(f => f.error), 0.0001);

  return (
    <Card className="h-full bg-card/30 border-white/5 backdrop-blur-md overflow-hidden flex flex-col">
      <CardHeader className="p-4 border-b border-white/5 bg-white/5 flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-sm font-mono font-bold uppercase tracking-wider flex items-center gap-2">
          <BrainCircuit className="h-4 w-4 text-neon-cyan" />
          Explainable AI (XAI)
        </CardTitle>
        <div className="flex items-center gap-2">
          {hasRealData && (
            <Badge variant="outline" className="text-[9px] border-emerald-500/30 text-emerald-400 h-5 gap-1">
              <Cpu className="h-2.5 w-2.5" />
              LIVE
            </Badge>
          )}
          <Tooltip>
            <TooltipTrigger>
              <Info className="h-4 w-4 text-muted-foreground" />
            </TooltipTrigger>
            <TooltipContent className="bg-popover border-white/10 text-[10px] max-w-[240px] font-mono">
              VAE per-feature reconstruction error identifies which behavioral dimensions deviate most from the learned normal manifold.
            </TooltipContent>
          </Tooltip>
        </div>
      </CardHeader>
      
      <CardContent className="p-4 flex-1 flex flex-col">
        {/* Risk Score Header */}
        <div className="flex justify-between items-center mb-6">
          <div className="text-center">
            <p className="text-[10px] text-muted-foreground font-mono uppercase">Detection</p>
            <p className="text-xs font-bold font-mono text-slate-400 uppercase tracking-widest mt-1">
              {anomaly.riskScore > 85 ? "CRITICAL" : anomaly.riskScore > 50 ? "ELEVATED" : "NORMAL"}
            </p>
          </div>
          <div className="h-px flex-1 bg-white/10 mx-4 relative">
             <div className="absolute top-1/2 left-0 w-full flex justify-between -translate-y-1/2">
                <div className="h-2 w-px bg-white/20" />
                <div className="h-2 w-px bg-white/20" />
             </div>
          </div>
          <div className="text-center">
            <p className="text-[10px] text-muted-foreground font-mono uppercase">Risk Score</p>
            <p className={cn(
              "text-xl font-bold font-mono",
              anomaly.riskScore > 85 ? "text-red-500" : anomaly.riskScore > 50 ? "text-orange-400" : "text-emerald-400"
            )}>{anomaly.riskScore}</p>
          </div>
        </div>

        {hasRealData ? (
          <>
            {/* Section label */}
            <p className="text-[9px] font-bold uppercase tracking-[0.2em] text-slate-600 mb-4">
              Top Anomalous Dimensions
            </p>

            {/* Feature bars — pure CSS, no chart libs */}
            <div className="space-y-3 flex-1">
              {features.map((feature, idx) => {
                const pct = (feature.error / maxError) * 100;
                const friendlyName = getFriendlyName(feature.name);
                
                return (
                  <div key={idx} className="group">
                    {/* Label row */}
                    <div className="flex justify-between items-baseline mb-1.5">
                      <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest truncate max-w-[140px]" title={feature.name}>
                        {friendlyName}
                      </span>
                      <span className={cn(
                        "text-[10px] font-mono font-black tabular-nums",
                        getBarTextColor(pct)
                      )}>
                        {feature.error.toFixed(4)}
                      </span>
                    </div>
                    
                    {/* Bar */}
                    <div className="w-full h-2.5 bg-white/[0.03] rounded-sm overflow-hidden relative">
                      <motion.div
                        initial={{ width: 0, opacity: 0 }}
                        animate={{ width: `${Math.max(pct, 3)}%`, opacity: 1 }}
                        transition={{ delay: idx * 0.12 + 0.3, duration: 0.6, ease: "easeOut" }}
                        className={cn(
                          "h-full rounded-sm transition-all",
                          getBarColor(pct)
                        )}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <Cpu className="h-8 w-8 text-slate-700 mx-auto mb-3" />
              <p className="text-[10px] text-slate-600 font-mono uppercase tracking-widest">
                Awaiting VAE inference data
              </p>
              <p className="text-[9px] text-slate-700 font-mono mt-1">
                Feature attribution will appear after ML scoring
              </p>
            </div>
          </div>
        )}

        <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">
          <p className="text-[10px] text-muted-foreground font-mono italic">
            {hasRealData ? `${features.length} features · per-dim MSE` : "No data available"}
          </p>
          <Badge variant="outline" className={cn(
            "text-[10px] h-5",
            hasRealData
              ? "border-emerald-500/20 text-emerald-400"
              : "border-white/10 text-slate-600"
          )}>
            {hasRealData ? "XAI LIVE" : "XAI v2.4"}
          </Badge>
        </div>
      </CardContent>
    </Card>
  );
}
