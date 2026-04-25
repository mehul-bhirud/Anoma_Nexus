"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MOCK_TRAJECTORY } from "@/lib/mock-data";
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  Area, 
  AreaChart 
} from "recharts";
import { Activity, TrendingDown } from "lucide-react";

export function BehavioralTrajectory() {
  return (
    <Card className="h-full bg-card/30 border-white/5 backdrop-blur-md overflow-hidden flex flex-col">
      <CardHeader className="p-4 border-b border-white/5 bg-white/5 flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-sm font-mono font-bold uppercase tracking-wider flex items-center gap-2">
          <Activity className="h-4 w-4 text-neon-cyan" />
          Behavioral Risk Trajectory
        </CardTitle>
        <div className="flex items-center gap-2 text-[10px] text-neon-cyan font-mono animate-pulse">
            <TrendingDown className="h-3 w-3" />
            DECAY ACTIVE (DF=0.15)
        </div>
      </CardHeader>
      
      <CardContent className="p-4 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={MOCK_TRAJECTORY}>
            <defs>
              <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#00d8ff" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#00d8ff" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.05)" />
            <XAxis 
              dataKey="time" 
              axisLine={false} 
              tickLine={false} 
              tick={{ fontSize: 10, fill: 'rgba(255,255,255,0.4)', fontFamily: 'monospace' }}
            />
            <YAxis 
              domain={[0, 100]} 
              axisLine={false} 
              tickLine={false} 
              tick={{ fontSize: 10, fill: 'rgba(255,255,255,0.4)', fontFamily: 'monospace' }}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: 'rgba(0,0,0,0.8)', 
                borderColor: 'rgba(255,255,255,0.1)',
                fontSize: '12px',
                fontFamily: 'monospace',
                borderRadius: '8px',
                backdropFilter: 'blur(8px)'
              }}
              itemStyle={{ color: '#00d8ff' }}
            />
            <Area 
              type="monotone" 
              dataKey="score" 
              stroke="#00d8ff" 
              strokeWidth={2}
              fillOpacity={1} 
              fill="url(#colorScore)" 
              animationDuration={2000}
            />
            {/* Decay Baseline */}
            <Line 
               type="monotone" 
               dataKey={() => 15} 
               stroke="rgba(255,255,255,0.1)" 
               strokeDasharray="5 5"
               strokeWidth={1}
               dot={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
