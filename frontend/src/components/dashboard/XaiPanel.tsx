"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { MOCK_SHAP_DATA, Anomaly } from "@/lib/mock-data";
import { motion } from "framer-motion";
import { BrainCircuit, Info } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

interface XaiPanelProps {
  anomaly: Anomaly | null;
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

  // Create deterministic hash from ID to pick a diverse set of SHAP features
  const hash = anomaly.id.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const mockKeys = Object.keys(MOCK_SHAP_DATA);
  const features = MOCK_SHAP_DATA[mockKeys[hash % mockKeys.length]];
  const baseValue = 10;
  let currentTotal = baseValue;

  return (
    <Card className="h-full bg-card/30 border-white/5 backdrop-blur-md overflow-hidden flex flex-col">
      <CardHeader className="p-4 border-b border-white/5 bg-white/5 flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-sm font-mono font-bold uppercase tracking-wider flex items-center gap-2">
          <BrainCircuit className="h-4 w-4 text-neon-cyan" />
          Explainable AI (SHAP)
        </CardTitle>
        <Tooltip>
          <TooltipTrigger>
            <Info className="h-4 w-4 text-muted-foreground" />
          </TooltipTrigger>
          <TooltipContent className="bg-popover border-white/10 text-[10px] max-w-[200px] font-mono">
            SHAP (SHapley Additive exPlanations) shows how each behavioral feature contributed to the final risk score.
          </TooltipContent>
        </Tooltip>
      </CardHeader>
      
      <CardContent className="p-4 flex-1 flex flex-col">
        <div className="flex justify-between items-center mb-6">
          <div className="text-center">
            <p className="text-[10px] text-muted-foreground font-mono uppercase">Base Value</p>
            <p className="text-lg font-bold font-mono text-muted-foreground">{baseValue}</p>
          </div>
          <div className="h-px flex-1 bg-white/10 mx-4 relative">
             <div className="absolute top-1/2 left-0 w-full flex justify-between -translate-y-1/2">
                <div className="h-2 w-px bg-white/20" />
                <div className="h-2 w-px bg-white/20" />
             </div>
          </div>
          <div className="text-center">
            <p className="text-[10px] text-muted-foreground font-mono uppercase">Risk Score</p>
            <p className="text-xl font-bold font-mono text-neon-red">{(anomaly.reconstructionLoss * 100).toFixed(0)}</p>
          </div>
        </div>

        <div className="space-y-4 relative flex-1">
          {features.map((feature, idx) => {
            const startX = (currentTotal / 100) * 100;
            currentTotal += feature.value;
            const endX = (currentTotal / 100) * 100;
            
            const isPositive = feature.value > 0;
            const left = Math.min(startX, endX);
            const width = Math.abs(feature.value);

            return (
              <div key={idx} className="relative h-8 flex items-center">
                <div className="w-24 shrink-0 text-[10px] font-mono text-muted-foreground truncate uppercase pr-2" title={feature.name}>
                  {feature.name}
                </div>
                
                <div className="flex-1 bg-white/5 h-full rounded-sm relative overflow-hidden">
                   {/* Zero Line */}
                   <div className="absolute h-full w-px bg-white/10 left-[10%]" />
                   
                   <motion.div
                    initial={{ width: 0, opacity: 0 }}
                    animate={{ width: `${width}%`, opacity: 1 }}
                    transition={{ delay: idx * 0.1 + 0.5, duration: 0.5 }}
                    className={`absolute h-4 top-2 rounded-sm ${isPositive ? 'bg-neon-red/60 shadow-[0_0_8px_rgba(255,0,0,0.3)]' : 'bg-neon-cyan/60 shadow-[0_0_8px_rgba(0,216,255,0.3)]'}`}
                    style={{ left: `${left}%` }}
                   />
                </div>
                
                <div className={`w-10 text-right text-[10px] font-mono font-bold ${isPositive ? 'text-neon-red' : 'text-neon-cyan'}`}>
                  {isPositive ? '+' : ''}{feature.value}
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between italic">
          <p className="text-[10px] text-muted-foreground font-mono">Contribution total analysis complete.</p>
          <Badge variant="outline" className="text-[10px] border-neon-cyan/20 text-neon-cyan h-5">XAI v2.4</Badge>
        </div>
      </CardContent>
    </Card>
  );
}
