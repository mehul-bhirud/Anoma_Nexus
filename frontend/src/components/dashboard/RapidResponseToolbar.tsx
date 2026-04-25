"use client";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ShieldX, Lock, KeyRound, Terminal, AlertTriangle } from "lucide-react";
import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

export function RapidResponseToolbar() {
  const [activeAction, setActiveAction] = useState<string | null>(null);

  const actions = [
    { id: "isolate", label: "Isolate Host", icon: ShieldX, color: "text-neon-red", border: "border-neon-red/50", bg: "bg-neon-red/10" },
    { id: "revoke", label: "Revoke Access", icon: Lock, color: "text-neon-orange", border: "border-neon-orange/50", bg: "bg-neon-orange/10" },
    { id: "reset", label: "Force Reset", icon: KeyRound, color: "text-neon-green", border: "border-neon-green/50", bg: "bg-neon-green/10" },
  ];

  return (
    <Card className="h-full bg-card/30 border-white/5 backdrop-blur-md overflow-hidden flex flex-col">
      <CardHeader className="p-4 border-b border-white/5 bg-white/5 flex flex-row items-center justify-between space-y-0 text-amber-500">
        <CardTitle className="text-sm font-mono font-bold uppercase tracking-wider flex items-center gap-2">
          <Terminal className="h-4 w-4" />
          Rapid Response Toolbar
        </CardTitle>
        <AlertTriangle className="h-4 w-4 animate-pulse" />
      </CardHeader>
      
      <CardContent className="p-4 flex-1 flex flex-col justify-center gap-4">
        <div className="grid grid-cols-1 gap-2">
          {actions.map((action) => (
            <Button
              key={action.id}
              variant="outline"
              className={`h-12 justify-start gap-4 border-white/5 bg-white/5 hover:bg-white/10 ${activeAction === action.id ? action.border + ' ' + action.bg : ''} transition-all duration-300`}
              onClick={() => setActiveAction(action.id)}
            >
              <action.icon className={`h-5 w-5 ${activeAction === action.id ? action.color : 'text-muted-foreground'}`} />
              <div className="flex flex-col items-start">
                <span className="text-xs font-mono font-bold uppercase tracking-widest">{action.label}</span>
                <span className="text-[9px] text-muted-foreground uppercase opacity-50">L3 AUTHORIZATION REQ</span>
              </div>
            </Button>
          ))}
        </div>

        <AnimatePresence mode="wait">
          {activeAction ? (
            <motion.div
              key={activeAction}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="mt-4 p-3 rounded border border-neon-red/30 bg-neon-red/5"
            >
              <p className="text-[11px] font-mono text-neon-red mb-2 uppercase font-bold tracking-tight">
                Confirm {activeAction.toUpperCase()} for m.nagar?
              </p>
              <div className="flex gap-2">
                <Button size="sm" className="flex-1 bg-neon-red hover:bg-neon-red/80 text-black text-[10px] font-mono font-bold h-7 uppercase">Execute</Button>
                <Button size="sm" variant="ghost" className="flex-1 text-[10px] font-mono h-7 uppercase" onClick={() => setActiveAction(null)}>Cancel</Button>
              </div>
            </motion.div>
          ) : (
            <div className="mt-4 p-3 rounded border border-white/5 bg-black/20 flex items-center justify-center italic">
              <p className="text-[10px] text-muted-foreground font-mono">Standby for containment instructions.</p>
            </div>
          )}
        </AnimatePresence>
      </CardContent>
    </Card>
  );
}
