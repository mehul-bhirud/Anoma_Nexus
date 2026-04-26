import { useState, useEffect, useRef, useCallback } from "react";
import { Anomaly } from "@/lib/mock-data";

// ── SOAR Action payload shape (from backend /api/isolate/{uid}) ──────────
interface SOARAction {
  type: "SOAR_ACTION";
  action: "ISOLATE" | "REVOKE";
  uid: string;
  status: string;
  timestamp: string;
  message: string;
}

export function useAegisStream() {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [connectionStatus, setConnectionStatus] = useState(false);
  const [isIntegrityVerified, setIsIntegrityVerified] = useState(true);
  const [merkleRoot, setMerkleRoot] = useState<string>("");
  const [backendStats, setBackendStats] = useState<any | null>(null);
  const socketRef = useRef<WebSocket | null>(null);

  // ── SOAR: Track which user IDs have been isolated/revoked ──────────
  const [isolatedUsers, setIsolatedUsers] = useState<Set<string>>(new Set());
  const [soarActions, setSoarActions] = useState<SOARAction[]>([]);

  useEffect(() => {
    // Attempt real connection to FastAPI
    const connect = () => {
      try {
        const wsHost = window.location.hostname || "127.0.0.1";
        const socket = new WebSocket(`ws://${wsHost}:8000/ws/stream`);
        socketRef.current = socket;

        socket.onopen = () => {
          setConnectionStatus(true);
          console.log("AEGIS-FUSION: WebSocket Uplink Established.");
        };

        socket.onmessage = (event) => {
          const data = JSON.parse(event.data);
          
          // ── SOAR ACTION HANDLER ────────────────────────────────────
          // Intercept {"type": "SOAR_ACTION"} payloads BEFORE anything else.
          // These are broadcast by the backend when an analyst clicks
          // "Isolate Host" or "Revoke Access" on ANY connected dashboard.
          if (data.type === "SOAR_ACTION") {
            const action = data as SOARAction;
            console.log(
              `%c🔒 SOAR: ${action.action} → ${action.uid}`,
              "color: #ff4444; font-weight: bold; font-size: 14px;"
            );
            // Add the UID to the isolated set so UI can flash red
            setIsolatedUsers(prev => new Set(prev).add(action.uid));
            setSoarActions(prev => [...prev, action]);
            return; // Don't process as a normal log
          }

          if (data.pong) {
            if (data.stats) {
              setBackendStats(data.stats);
              if (data.stats.merkle_root) {
                setMerkleRoot(data.stats.merkle_root);
                if (data.stats.merkle_root.includes("CORRUPTED") || data.stats.merkle_root === "CHAIN_BROKEN") {
                  setIsIntegrityVerified(false);
                } else {
                  setIsIntegrityVerified(true);
                }
              }
            }
            return; // Ignore heartbeat responses for the main feed
          }
          
          // Verify Merkle Integrity
          const root = data?.aegis_analysis?.merkle_root || data?.merkle_root;
          if (root) {
            setMerkleRoot(root);
            if (data?.event_type === "tamper_alert" || root === "CHAIN_BROKEN" || root.includes("CORRUPTED")) {
               setIsIntegrityVerified(false);
            } else {
               setIsIntegrityVerified(root !== "INVALID");
            }
          }

          // Only store critical alerts to prevent flushing the list with 0-risk logs
          if (data?.event_type === "critical_alert") {
            const newAnomaly: Anomaly = {
              id: data?.id || `STREAM-${Date.now()}-${crypto.randomUUID().split('-')[0]}`,
              user: data?.raw_log?.actor?.user?.uid ?? data?.user_id ?? "Unknown Entity",
              timestamp: data?.timestamp || new Date().toISOString(),
              type: data?.raw_log?.action_type ?? data?.type ?? "Neural Anomaly",
              severity: data?.severity ?? "Suspicious",
              description: data?.raw_log?.resource?.name ?? data?.description ?? "Real-time telemetry hit detected.",
              reconstructionLoss: data?.reconstructionLoss ?? (data?.risk_score ? data.risk_score / 100 : 0.45),
              riskScore: data?.risk_score ?? data?.aegis_analysis?.risk_score ?? 0,
              aiSummary: data?.ai_analysis?.summary ?? data?.aegis_analysis?.summary ?? "",
              location: data?.location ?? "Global Mesh",
              hourlyActivity: data?.hourlyActivity ?? [],
              // XAI: Real-time feature attribution from VAE reconstruction error
              xai_top_features: data?.xai_top_features ?? [],
            };

            // Phase 1: Append to standard 75-limit array
            setAnomalies(prev => [...prev, newAnomaly].slice(-75));
          }
        };

        socket.onclose = () => {
          setConnectionStatus(false);
          console.log("AEGIS-FUSION: WebSocket Uplink Terminated. Retrying...");
          setTimeout(connect, 3000); // 3-second auto-reconnect
        };

        socket.onerror = (err) => {
          console.error("WebSocket Error:", err);
          socket.close();
        };
      } catch (e) {
        console.error("Connection Failed:", e);
      }
    };

    connect();

    return () => {
      if (socketRef.current) socketRef.current.close();
    };
  }, []);

  // Phase 3: Heartbeat
  useEffect(() => {
    const pingInterval = setInterval(() => {
      if (socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send("ping");
      }
    }, 5000);

    return () => clearInterval(pingInterval);
  }, []);

  // ── SOAR: One-call helper to isolate a host from any component ─────
  // Usage:  const { isolateHost } = useAegisStream();
  //         onClick={() => isolateHost("emp_0031")}
  const isolateHost = useCallback(async (uid: string) => {
    const wsHost = window.location.hostname || "127.0.0.1";
    try {
      const res = await fetch(`http://${wsHost}:8000/api/isolate/${uid}`, {
        method: "POST",
      });
      const data = await res.json();
      console.log("SOAR Isolate response:", data);
      return data;
    } catch (err) {
      console.error("SOAR Isolate failed:", err);
    }
  }, []);

  // ── SOAR: Helper to revoke access ──────────────────────────────────
  const revokeAccess = useCallback(async (uid: string) => {
    const wsHost = window.location.hostname || "127.0.0.1";
    try {
      const res = await fetch(`http://${wsHost}:8000/api/revoke/${uid}`, {
        method: "POST",
      });
      const data = await res.json();
      console.log("SOAR Revoke response:", data);
      return data;
    } catch (err) {
      console.error("SOAR Revoke failed:", err);
    }
  }, []);

  return {
    anomalies,
    connectionStatus,
    isIntegrityVerified,
    merkleRoot,
    backendStats,
    // SOAR exports
    isolatedUsers,
    soarActions,
    isolateHost,
    revokeAccess,
  };
}
