"use client";

import { useState, useEffect } from "react";
import { 
  ShieldAlert, 
  MapPin, 
  Activity, 
  Lock, 
  PlayCircle,
  Clock,
  ExternalLink,
  Ban,
  Fingerprint,
  AlertTriangle,
  BrainCircuit,
  FileWarning,
  Zap,
  ChevronRight,
  Search
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { ThreatModal } from "@/components/dashboard/ThreatModal";
import { useAegisStream } from "@/hooks/use-aegis-stream";
import { motion, AnimatePresence } from "framer-motion";

// ── Helpers to extract data from any anomaly ────────────────────────────────

function extractUser(a: any): string {
  return a?.raw_log?.actor?.user_id
    || a?.raw_log?.actor?.user?.uid
    || a?.user
    || "Unknown Entity";
}

function extractDepartment(a: any): string {
  return a?.raw_log?.actor?.department
    || a?.user_context?.department
    || a?.location
    || "System Access";
}

function extractIP(a: any): string {
  return a?.raw_log?.context?.ip_address || "—";
}

function extractDevice(a: any): string {
  return a?.raw_log?.context?.device_type || "—";
}

function extractLocation(a: any): string {
  return a?.raw_log?.context?.location || a?.location || "—";
}

function extractResource(a: any): string {
  return a?.raw_log?.resource?.name || a?.description || "—";
}

function extractVolume(a: any): number {
  return a?.raw_log?.resource?.volume_mb || 0;
}

function extractActionType(a: any): string {
  return a?.raw_log?.action?.type
    || a?.raw_log?.action_type
    || a?.type
    || "Unknown Action";
}

function extractThreatVectors(a: any): string[] {
  return a?.ai_analysis?.threat_vectors
    || a?.threat_vectors
    || [a?.type || "Neural Anomaly"];
}

function extractSummary(a: any): string {
  return a?.ai_analysis?.summary
    || a?.aiSummary
    || "";
}

function extractRecommendation(a: any): string {
  return a?.ai_analysis?.recommended_action || "Escalate to SOC Lead for manual review.";
}

function extractTimestamp(a: any): string {
  return a?.timestamp || new Date().toISOString();
}

function extractRiskScore(a: any): number {
  return a?.riskScore || a?.risk_score || 0;
}

function getInitials(name: string): string {
  return name
    .split(/[\s._]+/)
    .filter(Boolean)
    .map(p => p[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

function getSeverityColor(score: number): string {
  if (score >= 85) return "text-red-500";
  if (score >= 60) return "text-orange-500";
  if (score >= 30) return "text-yellow-500";
  return "text-emerald-500";
}

function getSeverityLabel(score: number): string {
  if (score >= 85) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "MEDIUM";
  return "LOW";
}

function getSeverityBadgeClass(score: number): string {
  if (score >= 85) return "bg-red-900/40 text-red-500 border-red-900/30";
  if (score >= 60) return "bg-orange-900/30 text-orange-500 border-orange-900/30";
  if (score >= 30) return "bg-yellow-900/30 text-yellow-500 border-yellow-900/30";
  return "bg-emerald-900/30 text-emerald-500 border-emerald-900/30";
}

function getPlaybookForAlert(a: any): { title: string; desc: string; active: boolean }[] {
  const score = extractRiskScore(a);
  const action = extractActionType(a);
  const vectors = extractThreatVectors(a);
  const vectorStr = vectors.join(" ").toLowerCase();

  const playbooks: { title: string; desc: string; active: boolean }[] = [];

  if (vectorStr.includes("honey") || vectorStr.includes("deception")) {
    playbooks.push({ title: "Honey-Trap Response Protocol", desc: "Trace canary file access chain & isolate actor", active: true });
    playbooks.push({ title: "Evidence Preservation Chain", desc: "Forensic logging for incident report", active: true });
  } else if (vectorStr.includes("geofence") || vectorStr.includes("external")) {
    playbooks.push({ title: "Network Perimeter Lockdown", desc: "Block external session tokens & alert physical security", active: true });
    playbooks.push({ title: "VPN Policy Enforcement", desc: "Require corporate VPN for document access", active: false });
  } else if (vectorStr.includes("forensic") || vectorStr.includes("stego")) {
    playbooks.push({ title: "Digital Forensics Extraction", desc: "Recover embedded watermarks from leaked artifacts", active: true });
    playbooks.push({ title: "Legal Hold & Chain of Custody", desc: "Preserve evidence for legal proceedings", active: true });
  } else if (action.includes("download") || action.includes("exfil") || extractVolume(a) > 500) {
    playbooks.push({ title: "Data Exfiltration Response v4", desc: "Automated containment for data egress", active: true });
    playbooks.push({ title: "DLP Policy Tightening", desc: "Restrict USB and cloud upload channels", active: false });
  } else if (score >= 85) {
    playbooks.push({ title: "Standard Isolation Protocol v4", desc: "Automated containment for user accounts", active: true });
    playbooks.push({ title: "Evidence Preservation Chain", desc: "Forensic logging for HR review", active: true });
  } else {
    playbooks.push({ title: "Enhanced Monitoring", desc: "30-minute behavioral watch with passive logging", active: true });
    playbooks.push({ title: "Standard Escalation Path", desc: "Route to SOC L2 for manual triage", active: false });
  }

  return playbooks;
}


// ═══════════════════════════════════════════════════════════════════════════
//  MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════════

export default function ResponsePage() {
  const { anomalies } = useAegisStream();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isThreatModalOpen, setIsThreatModalOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // Auto-select the latest alert when stream updates (if nothing selected)
  useEffect(() => {
    if (!selectedId && anomalies.length > 0) {
      setSelectedId(anomalies[anomalies.length - 1].id);
    }
  }, [anomalies, selectedId]);

  // Reverse for newest-first in sidebar
  const sortedAnomalies = [...anomalies].reverse();
  
  // Filter by search
  const filteredAnomalies = searchQuery
    ? sortedAnomalies.filter(a => {
        const q = searchQuery.toLowerCase();
        return extractUser(a).toLowerCase().includes(q)
          || extractActionType(a).toLowerCase().includes(q)
          || extractResource(a).toLowerCase().includes(q)
          || extractDepartment(a).toLowerCase().includes(q);
      })
    : sortedAnomalies;

  const selected = anomalies.find(a => a.id === selectedId) || anomalies[anomalies.length - 1];

  if (!selected) {
    return (
      <div className="flex h-[calc(100vh-140px)] items-center justify-center">
        <div className="text-center space-y-4">
          <ShieldAlert className="h-16 w-16 text-slate-700 mx-auto" />
          <h2 className="text-xl font-bold text-slate-400 font-heading">Awaiting Threat Telemetry</h2>
          <p className="text-sm text-slate-600">Start the stream to begin receiving alerts in real-time.</p>
        </div>
      </div>
    );
  }

  const user = extractUser(selected);
  const dept = extractDepartment(selected);
  const ip = extractIP(selected);
  const device = extractDevice(selected);
  const location = extractLocation(selected);
  const resource = extractResource(selected);
  const volume = extractVolume(selected);
  const action = extractActionType(selected);
  const vectors = extractThreatVectors(selected);
  const summary = extractSummary(selected);
  const recommendation = extractRecommendation(selected);
  const timestamp = extractTimestamp(selected);
  const riskScore = extractRiskScore(selected);
  const playbooks = getPlaybookForAlert(selected);

  const handleCommandInvoke = (label: string) => {
    if (label === "Revoke Access" || label === "Isolate Host") {
      setIsThreatModalOpen(true);
    }
  };

  return (
    <>
      <ThreatModal 
        threat={selected}
        isOpen={isThreatModalOpen}
        onClose={() => setIsThreatModalOpen(false)}
        onAction={(act) => {
          console.log(`Action: ${act} for ${user}`);
          setIsThreatModalOpen(false);
        }}
      />
      <div className="grid grid-cols-12 gap-8 h-[calc(100vh-140px)]">
        {/* ── Left Column: ALL Alerts ── */}
        <aside className="col-span-12 lg:col-span-4 flex flex-col gap-4">
          <div className="bg-[#0A0E14] p-5 border border-white/[0.03] flex-1 flex flex-col min-h-0">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-[10px] font-bold font-heading uppercase tracking-[0.2em] text-slate-500">Incident Queue</h3>
              <Badge className="bg-red-900/10 text-red-500 border-red-900/20 text-[10px] uppercase font-bold px-2 py-0.5 rounded-sm">
                {anomalies.length} Alert{anomalies.length !== 1 ? "s" : ""}
              </Badge>
            </div>

            {/* Search */}
            <div className="relative mb-4">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-600" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search user, action, resource..."
                className="w-full bg-black/40 border border-white/[0.05] pl-9 pr-3 py-2 text-xs rounded-sm focus:ring-1 focus:ring-primary outline-none text-slate-300 placeholder:text-slate-700"
              />
            </div>

            <ScrollArea className="flex-1">
              <div className="flex flex-col gap-2 pr-3">
                <AnimatePresence initial={false}>
                  {filteredAnomalies.map((a) => {
                    const aUser = extractUser(a);
                    const aScore = extractRiskScore(a);
                    const aAction = extractActionType(a);
                    const aTime = extractTimestamp(a);
                    const isSelected = a.id === selectedId;
                    const aVectors = extractThreatVectors(a);

                    return (
                      <motion.div
                        key={a.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        onClick={() => setSelectedId(a.id)}
                        className={cn(
                          "group bg-black/20 hover:bg-[#141A23] transition-all p-4 rounded-sm border cursor-pointer relative overflow-hidden",
                          isSelected
                            ? "border-primary/30 bg-[#141A23] shadow-lg shadow-primary/5"
                            : "border-white/[0.03]"
                        )}
                      >
                        {isSelected && (
                          <div className="absolute left-0 top-0 bottom-0 w-1 bg-primary" />
                        )}

                        <div className="flex items-start gap-3">
                          {/* Avatar */}
                          <div className={cn(
                            "w-10 h-10 rounded-sm flex items-center justify-center font-bold text-xs border shrink-0",
                            aScore >= 85
                              ? "bg-red-950/30 border-red-500/30 text-red-500"
                              : aScore >= 60
                              ? "bg-orange-950/20 border-orange-500/20 text-orange-500"
                              : "bg-[#0A0E14] border-white/5 text-slate-500"
                          )}>
                            {getInitials(aUser)}
                          </div>

                          {/* Info */}
                          <div className="flex-1 min-w-0">
                            <div className="flex justify-between items-start">
                              <p className="text-sm font-bold text-slate-200 truncate max-w-[120px]">{aUser}</p>
                              <span className={cn("text-sm font-black font-heading tracking-tighter", getSeverityColor(aScore))}>
                                {aScore}
                              </span>
                            </div>
                            <p className="text-[9px] text-slate-600 font-bold uppercase tracking-widest mt-1 truncate">{aAction}</p>
                            <div className="flex items-center gap-2 mt-2">
                              <Badge variant="outline" className={cn("text-[8px] font-bold border px-1.5 py-0 rounded-sm", getSeverityBadgeClass(aScore))}>
                                {getSeverityLabel(aScore)}
                              </Badge>
                              {aVectors.slice(0, 1).map((v, i) => (
                                <span key={i} className="text-[8px] bg-white/[0.03] px-1.5 py-0.5 rounded-sm text-slate-600 font-bold uppercase tracking-widest truncate max-w-[100px]">
                                  {v}
                                </span>
                              ))}
                            </div>
                          </div>

                          <ChevronRight className={cn(
                            "h-4 w-4 shrink-0 mt-1 transition-colors",
                            isSelected ? "text-primary" : "text-slate-800"
                          )} />
                        </div>

                        {/* Timestamp */}
                        <p className="text-[8px] text-slate-700 font-mono mt-2 pl-[52px]">
                          {new Date(aTime).toLocaleTimeString()} — {new Date(aTime).toLocaleDateString()}
                        </p>
                      </motion.div>
                    );
                  })}
                </AnimatePresence>

                {filteredAnomalies.length === 0 && (
                  <div className="text-center py-10 text-slate-600 text-xs">
                    {searchQuery ? "No matching alerts found." : "No alerts received yet."}
                  </div>
                )}
              </div>
            </ScrollArea>
          </div>

          {/* MTTR Stats */}
          <div className="bg-[#0A0E14] p-5 border border-white/[0.03] border-l-primary border-l-2">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-primary/5 rounded-sm border border-primary/10">
                <Clock className="h-6 w-6 text-primary" />
              </div>
              <div>
                <p className="text-[10px] text-slate-600 font-bold uppercase tracking-widest leading-none mb-1">Active Cases</p>
                <p className="text-2xl font-black font-heading text-slate-200 tracking-tighter">{anomalies.length}</p>
              </div>
              <div className="ml-auto text-right">
                <p className="text-[10px] text-slate-600 font-bold uppercase tracking-widest leading-none mb-1">Highest Risk</p>
                <p className={cn("text-2xl font-black font-heading tracking-tighter",
                  getSeverityColor(Math.max(...anomalies.map(extractRiskScore), 0))
                )}>
                  {Math.max(...anomalies.map(extractRiskScore), 0)}
                </p>
              </div>
            </div>
          </div>
        </aside>

        {/* ── Right Column: Selected Alert Detail ── */}
        <section className="col-span-12 lg:col-span-8 flex flex-col gap-6 overflow-y-auto pr-2">
          {/* Main Card */}
          <div className="bg-[#0A0E14] p-8 border border-white/[0.03] relative overflow-hidden">
            <div className="absolute -top-32 -right-32 w-80 h-80 bg-primary/[0.03] blur-[100px] rounded-full pointer-events-none" />
            
            <div className="relative z-10">
              <div className="flex justify-between items-start mb-10">
                <div>
                  <span className={cn(
                    "text-[10px] border px-3 py-1 rounded-sm font-bold uppercase tracking-[0.2em]",
                    riskScore >= 85
                      ? "bg-red-900/10 text-red-500 border-red-900/30"
                      : riskScore >= 60
                      ? "bg-orange-900/10 text-orange-500 border-orange-900/30"
                      : "bg-yellow-900/10 text-yellow-500 border-yellow-900/30"
                  )}>
                    {riskScore >= 85 ? "IMMEDIATE ATTENTION REQUIRED" : riskScore >= 60 ? "ELEVATED THREAT" : "MONITORING"}
                  </span>
                  <h2 className="text-3xl font-black font-heading mt-4 tracking-tighter text-slate-100">
                    {user} <span className="text-slate-600 font-light truncate">({dept})</span>
                  </h2>
                  <div className="flex items-center gap-4 mt-3 text-[10px] text-slate-600 uppercase font-bold tracking-widest flex-wrap">
                    <span className="flex items-center gap-1.5"><MapPin className="h-3.5 w-3.5" /> {location}</span>
                    <span className="flex items-center gap-1.5 font-mono"><Activity className="h-3.5 w-3.5" /> IP: {ip}</span>
                    <span className="flex items-center gap-1.5"><Lock className="h-3.5 w-3.5" /> Device: {device}</span>
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-[9px] text-slate-600 uppercase font-bold tracking-widest mb-1">Risk Score</p>
                  <p className={cn("text-5xl font-black font-heading tracking-tighter", getSeverityColor(riskScore))}>
                    {riskScore}
                  </p>
                  <p className={cn("text-[10px] font-bold uppercase tracking-widest mt-1", getSeverityColor(riskScore))}>
                    {getSeverityLabel(riskScore)}
                  </p>
                </div>
              </div>

              {/* Threat Vectors */}
              <div className="flex flex-wrap gap-2 mb-8">
                {vectors.map((v, i) => (
                  <span key={i} className="text-[9px] px-3 py-1.5 rounded-sm bg-red-950/20 text-red-400 border border-red-900/30 font-bold uppercase tracking-widest flex items-center gap-1.5">
                    <AlertTriangle className="h-3 w-3" /> {v}
                  </span>
                ))}
                <span className="text-[9px] px-3 py-1.5 rounded-sm bg-white/[0.02] text-slate-500 border border-white/[0.05] font-bold uppercase tracking-widest">
                  {action}
                </span>
                {resource !== "—" && (
                  <span className="text-[9px] px-3 py-1.5 rounded-sm bg-white/[0.02] text-slate-500 border border-white/[0.05] font-bold uppercase tracking-widest flex items-center gap-1.5">
                    <FileWarning className="h-3 w-3" /> {resource}
                  </span>
                )}
                {volume > 0 && (
                  <span className="text-[9px] px-3 py-1.5 rounded-sm bg-orange-950/20 text-orange-400 border border-orange-900/30 font-bold uppercase tracking-widest">
                    {volume >= 1000 ? `${(volume / 1000).toFixed(1)} GB` : `${volume.toFixed(0)} MB`}
                  </span>
                )}
              </div>

              {/* Action Control Panel */}
              <div className="grid grid-cols-3 gap-4 mb-10">
                <ActionButton icon={Ban} label="Isolate Host" danger onClick={() => handleCommandInvoke("Isolate Host")} />
                <ActionButton icon={Lock} label="Revoke Access" primary onClick={() => handleCommandInvoke("Revoke Access")} />
                <ActionButton icon={Fingerprint} label="Trigger MFA" success />
              </div>

              {/* AI Analysis */}
              {summary && (
                <div className="bg-black/20 p-6 border border-white/[0.03] rounded-sm mb-6">
                  <h4 className="text-[9px] font-bold uppercase tracking-[0.2em] text-slate-600 mb-4 flex items-center gap-2">
                    <BrainCircuit className="h-3.5 w-3.5 text-primary" /> AI-Generated Threat Narrative
                  </h4>
                  <p className="text-sm leading-relaxed text-slate-300 font-medium mb-4">{summary}</p>
                  <div className="flex items-start gap-2 bg-primary/5 border border-primary/10 p-3 rounded-sm">
                    <Zap className="h-4 w-4 text-primary shrink-0 mt-0.5" />
                    <p className="text-xs text-primary/80 font-medium">{recommendation}</p>
                  </div>
                </div>
              )}

              {/* Investigation Journal */}
              <div className="bg-black/20 p-6 border border-white/[0.03] rounded-sm">
                <div className="flex justify-between items-center mb-6">
                  <h4 className="text-[9px] font-bold uppercase tracking-[0.2em] text-slate-600">Analyst Investigation Journal</h4>
                  <div className="flex gap-2">
                    <button className="text-[8px] font-bold px-2 py-1 bg-white/[0.03] border border-white/[0.05] rounded-sm uppercase tracking-widest hover:bg-white/[0.05] text-slate-400">Attach Artifact</button>
                  </div>
                </div>
                <div className="grid grid-cols-12 gap-6">
                  <div className="col-span-4 space-y-4">
                    <div className="space-y-2">
                      <label className="text-[8px] uppercase font-bold text-slate-700 tracking-widest">Case Status</label>
                      <select defaultValue="Open" className="w-full bg-[#0A0E14] border border-white/[0.05] px-3 py-2 text-xs rounded-sm focus:ring-1 focus:ring-primary outline-none text-slate-300">
                        <option value="Open">Open</option>
                        <option value="In-Progress">In-Progress</option>
                        <option value="Resolved">Resolved</option>
                      </select>
                    </div>
                    <div className="space-y-2">
                      <label className="text-[8px] uppercase font-bold text-slate-700 tracking-widest">Timestamp</label>
                      <p className="text-xs font-mono text-slate-400">{new Date(timestamp).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="col-span-8 flex flex-col gap-2">
                    <label className="text-[8px] uppercase font-bold text-slate-700 tracking-widest">Remediation Notes</label>
                    <textarea 
                      className="w-full h-32 bg-[#0A0E14] border border-white/[0.05] p-3 text-xs rounded-sm focus:ring-1 focus:ring-primary outline-none resize-none placeholder:text-slate-800 text-slate-300" 
                      placeholder={`Document findings for ${user}...`} 
                    />
                    <div className="flex justify-end mt-2">
                      <button className="px-8 py-2 bg-primary text-black text-[10px] font-bold uppercase tracking-[0.2em] hover:opacity-90 transition-all active:scale-95">
                        Commit Response Log
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Bento: Data Volume + Playbook */}
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-[#0A0E14] p-5 border border-white/[0.03] flex flex-col gap-4">
              <h4 className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Event Data Volume</h4>
              <div className="flex-1 min-h-[140px] bg-black/40 rounded-sm flex flex-col items-center justify-center p-6 border border-white/[0.03] group relative overflow-hidden">
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(0,141,168,0.03)_0%,transparent_100%)] group-hover:scale-150 transition-transform duration-1000" />
                <span className={cn("text-4xl font-black font-heading relative z-10 tracking-tighter",
                  volume > 500 ? "text-red-500" : volume > 0 ? "text-slate-100" : "text-slate-500"
                )}>
                  {volume >= 1000 ? `${(volume / 1000).toFixed(1)} GB` : volume > 0 ? `${volume.toFixed(0)} MB` : "N/A"}
                </span>
                <span className="text-[10px] text-slate-700 uppercase font-bold tracking-widest mt-2 relative z-10">
                  {resource !== "—" ? resource : "No resource metadata"}
                </span>
                {volume > 0 && (
                  <div className="w-32 h-1 bg-white/[0.03] rounded-full mt-4 overflow-hidden relative z-10">
                    <div className={cn("h-full", volume > 500 ? "bg-red-900/60" : "bg-primary/40")} style={{ width: `${Math.min((volume / 1000) * 100, 100)}%` }} />
                  </div>
                )}
              </div>
            </div>
            <div className="bg-[#0A0E14] p-5 border border-white/[0.03] flex flex-col gap-4">
              <h4 className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Recommended Playbook</h4>
              <div className="space-y-2 flex-1">
                {playbooks.map((pb, i) => (
                  <PlaybookItem key={i} title={pb.title} desc={pb.desc} active={pb.active} />
                ))}
              </div>
            </div>
          </div>
        </section>
      </div>
    </>
  );
}


// ── Sub-Components ──────────────────────────────────────────────────────────

function ActionButton({ icon: Icon, label, primary, danger, success, onClick }: any) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "flex flex-col items-center justify-center gap-2 p-6 transition-all duration-300 group border rounded-sm relative overflow-hidden",
        danger 
          ? "bg-black/20 border-white/[0.05] hover:border-red-900/50 hover:bg-red-900/5" 
          : primary 
          ? "bg-black/20 border-white/[0.05] hover:border-primary/50 hover:bg-primary/5"
          : "bg-black/20 border-white/[0.05] hover:border-emerald-900/50 hover:bg-emerald-900/5"
      )}
    >
      <Icon className={cn(
        "h-8 w-8 transition-transform group-hover:scale-110",
        danger ? "text-red-500" : primary ? "text-primary" : "text-emerald-500"
      )} />
      <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500 group-hover:text-slate-300">{label}</span>
    </button>
  );
}

function PlaybookItem({ title, desc, active }: { title: string, desc: string, active?: boolean }) {
  return (
    <div className={cn(
      "p-3 rounded-sm border flex items-center gap-3 transition-all",
      active ? "bg-[#141A23] border-emerald-900/20" : "bg-black/20 border-white/[0.03] opacity-40"
    )}>
      <PlayCircle className={cn("h-4 w-4", active ? "text-emerald-500" : "text-slate-600")} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-bold text-slate-200 truncate">{title}</p>
        <p className="text-[8px] text-slate-600 font-bold uppercase truncate mt-1 tracking-widest">{desc}</p>
      </div>
      <ExternalLink className="h-3 w-3 text-slate-700" />
    </div>
  );
}
