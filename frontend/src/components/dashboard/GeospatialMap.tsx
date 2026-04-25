"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Anomaly } from "@/lib/mock-data";
import { motion } from "framer-motion";
import { Globe, MapPin } from "lucide-react";

interface GeospatialMapProps {
  anomaly: Anomaly | null;
}

export function GeospatialMap({ anomaly }: GeospatialMapProps) {
  // Mock coordinates for locations
  const coordinates: Record<string, { x: number; y: number }> = {
    "Mumbai, IN": { x: 70, y: 55 },
    "London, UK": { x: 45, y: 35 },
    "New York, US": { x: 25, y: 40 },
    "Berlin, DE": { x: 50, y: 35 },
  };

  const activeLoc = anomaly?.location ? coordinates[anomaly.location] : null;

  return (
    <Card className="h-full bg-card/30 border-white/5 backdrop-blur-md overflow-hidden flex flex-col">
      <CardHeader className="p-4 border-b border-white/5 bg-white/5 flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-sm font-mono font-bold uppercase tracking-wider flex items-center gap-2">
          <Globe className="h-4 w-4 text-neon-cyan" />
          Impossible Travel Detection
        </CardTitle>
      </CardHeader>
      
      <CardContent className="p-0 flex-1 relative bg-black/40">
        <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-20">
            {/* Simple Grid Background */}
            <div className="absolute inset-0" style={{ 
                backgroundImage: 'radial-gradient(circle, white 1px, transparent 1px)', 
                backgroundSize: '20px 20px' 
            }} />
        </div>

        <svg viewBox="0 0 100 70" className="w-full h-full p-4">
          {/* Stylized Continents (Simplified Shapes) */}
          <path 
            d="M15,30 Q20,25 30,35 T40,40 M45,30 Q50,25 60,30 T70,40 M75,50 Q80,55 85,60" 
            fill="none" 
            stroke="white" 
            strokeWidth="0.5" 
            strokeDasharray="2 2"
            className="opacity-10"
          />
          
          {/* Static Dots for major hubs */}
          <circle cx="25" cy="40" r="0.5" fill="white" className="opacity-20" />
          <circle cx="45" cy="35" r="0.5" fill="white" className="opacity-20" />
          <circle cx="70" cy="55" r="0.5" fill="white" className="opacity-20" />
          <circle cx="50" cy="35" r="0.5" fill="white" className="opacity-20" />

          {anomaly?.user === "j.doe" && (
             <>
               {/* Impossible Travel Path */}
               <motion.path
                 d="M25,40 L45,35"
                 stroke="url(#grad-red)"
                 strokeWidth="1"
                 fill="none"
                 initial={{ pathLength: 0 }}
                 animate={{ pathLength: 1 }}
                 transition={{ duration: 2, repeat: Infinity }}
               />
               <circle cx="25" cy="40" r="1.5" fill="#ff0000" className="animate-pulse" />
               <circle cx="45" cy="35" r="1.5" fill="#ff0000" className="animate-pulse" />
             </>
          )}

          {activeLoc && (
            <motion.g initial={{ opacity: 0, scale: 0 }} animate={{ opacity: 1, scale: 1 }}>
               <circle cx={activeLoc.x} cy={activeLoc.y} r="2" fill="none" stroke="currentColor" strokeWidth="0.5" className="text-neon-cyan" />
               <motion.circle 
                 cx={activeLoc.x} cy={activeLoc.y} r="2" 
                 fill="none" stroke="currentColor" strokeWidth="0.5" 
                 className="text-neon-cyan"
                 animate={{ scale: [1, 3], opacity: [1, 0] }}
                 transition={{ duration: 1.5, repeat: Infinity, ease: "easeOut" }}
               />
               <circle cx={activeLoc.x} cy={activeLoc.y} r="0.8" fill="white" className="text-neon-cyan" />
            </motion.g>
          )}

          <defs>
            <linearGradient id="grad-red" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ff0000" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#ff0000" stopOpacity="0.2" />
            </linearGradient>
          </defs>
        </svg>

        <div className="absolute bottom-2 left-2 flex flex-col gap-1">
             {anomaly?.location && (
                <div className="bg-black/60 backdrop-blur-md px-2 py-1 rounded border border-white/5 flex items-center gap-2">
                    <MapPin className="h-3 w-3 text-neon-cyan" />
                    <span className="text-[10px] font-mono text-white">{anomaly.location}</span>
                </div>
             )}
             {anomaly?.user === "j.doe" && (
                <div className="bg-neon-red/20 backdrop-blur-md px-2 py-1 rounded border border-neon-red/50 flex items-center gap-2 animate-pulse">
                    <AlertCircle className="h-3 w-3 text-neon-red" />
                    <span className="text-[10px] font-mono text-neon-red font-bold">IMP. TRAVEL RECONSTRUCTED</span>
                </div>
             )}
        </div>
      </CardContent>
    </Card>
  );
}

function AlertCircle(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}
