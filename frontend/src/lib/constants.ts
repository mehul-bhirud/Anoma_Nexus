export const API_BASE = "http://localhost:8000";

export const API_ENDPOINTS = {
  INJECT_LOG: `${API_BASE}/api/inject_test_log`,
  STREAM_START: `${API_BASE}/api/stream/start`,
  STREAM_STOP: `${API_BASE}/api/stream/stop`,
  STATS: `${API_BASE}/api/stats`,
  ALERTS: `${API_BASE}/api/alerts`,
  MERKLE: `${API_BASE}/api/merkle`,
  TAMPER: `${API_BASE}/api/tamper`,
  VERIFY_NETWORK: `${API_BASE}/api/verify-network`,
  USERS: `${API_BASE}/api/users`,
  USER_PERMISSIONS: `${API_BASE}/api/users/permissions`,
  DOWNLOAD_WATERMARKED: `${API_BASE}/api/download_watermarked`,
  EXTRACT_WATERMARK: `${API_BASE}/api/extract_watermark`,
  POLICY_ACTION: `${API_BASE}/api/policy-action`,
} as const;
