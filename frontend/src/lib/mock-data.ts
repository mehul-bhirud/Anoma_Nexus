export interface Anomaly {
  id: string;
  timestamp: string;
  user: string;
  type: string;
  severity: string;
  reconstructionLoss: number;
  riskScore: number;
  description: string;
  location?: string;
  hourlyActivity: number[]; // 24 hours of risk/activity scores (0-100)
  aiSummary?: string;
  merkle_root?: string;
  aegis_analysis?: {
    risk_score: number;
    merkle_root: string;
    summary: string;
    threat_vectors: string[];
    recommended_action: string;
  };
}

export interface ShapFeature {
  name: string;
  value: number;
}

export const MOCK_ANOMALIES: Anomaly[] = [
  {
    id: "1",
    timestamp: new Date().toISOString(),
    user: "m.nagar",
    type: "Traitor",
    severity: "Critical",
    reconstructionLoss: 0.92,
    riskScore: 92,
    description: "Bulk sensitive file download outside working hours",
    location: "Mumbai, IN",
    hourlyActivity: [5, 4, 3, 95, 88, 12, 10, 8, 45, 50, 55, 60, 40, 35, 30, 25, 20, 15, 10, 8, 6, 5, 4, 3],
  },
  {
    id: "2",
    timestamp: new Date(Date.now() - 5000).toISOString(),
    user: "j.doe",
    type: "Masquerader",
    severity: "Suspicious",
    reconstructionLoss: 0.74,
    riskScore: 74,
    description: "Concurrent login from New York and London",
    location: "London, UK",
    hourlyActivity: [10, 12, 15, 10, 8, 12, 14, 16, 18, 20, 22, 24, 85, 92, 78, 45, 30, 25, 20, 18, 16, 14, 12, 10],
  },
  {
    id: "3",
    timestamp: new Date(Date.now() - 15000).toISOString(),
    user: "a.smith",
    type: "Careless User",
    severity: "Normal",
    reconstructionLoss: 0.45,
    riskScore: 45,
    description: "Unusual number of failed VPN attempts",
    location: "Berlin, DE",
    hourlyActivity: [5, 6, 8, 10, 12, 15, 20, 25, 40, 55, 65, 75, 40, 35, 30, 25, 20, 18, 16, 14, 12, 10, 8, 6],
  },
];

export const MOCK_SHAP_DATA: Record<string, ShapFeature[]> = {
  "1": [
    { name: "Unusual Time", value: 30 },
    { name: "Large Download", value: 45 },
    { name: "Rare Extension", value: 12 },
    { name: "Trusted Device", value: -15 },
    { name: "Known Network", value: -10 },
  ],
  "2": [
    { name: "Geospatial Distance", value: 65 },
    { name: "Unusual OS", value: 15 },
    { name: "VPN Usage", value: 10 },
    { name: "Consistent IP", value: -5 },
  ],
};

export const MOCK_TRAJECTORY = [
  { time: "09:00", score: 20 },
  { time: "10:00", score: 25 },
  { time: "11:00", score: 85 }, // Breach
  { time: "12:00", score: 70 }, // Decay starts
  { time: "13:00", score: 60 },
  { time: "14:00", score: 50 },
  { time: "15:00", score: 40 },
];

export const MOCK_STATS = {
  mttd: "14m 20s",
  mttr: "42m 10s",
  riskScore: 68,
};
