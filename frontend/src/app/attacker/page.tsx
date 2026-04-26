"use client";

import React, { useState, useEffect, useRef } from 'react';
import { API_ENDPOINTS } from '@/lib/constants';

// â”€â”€ Phase types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
type Phase = "idle" | "opening" | "viewing" | "downloading" | "done" | "geofenced" | "policy_result";

// â”€â”€ User Identity Types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
interface MockUser {
    id: string;
    name: string;
    department: string;
}

// â”€â”€ Policy Action Definitions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
interface PolicyAction {
    key: string;
    label: string;
    icon: string;
    description: string;
}

const POLICY_ACTIONS: PolicyAction[] = [
    { key: "EXTERNAL_STORAGE_ALLOWED",   label: "USB Drive",         icon: "ðŸ’¾", description: "Mount removable media (USB / Pen Drive)" },
    { key: "UNRESTRICTED_WEB_BROWSING",  label: "Web Browser",       icon: "ðŸŒ", description: "Bypass corporate web content filter" },
    { key: "SOFTWARE_INSTALLATION",      label: "Install Software",  icon: "ðŸ“¦", description: "Download & install unapproved applications" },
    { key: "EXTERNAL_EMAIL_ATTACHMENTS", label: "Email Attachment",   icon: "ðŸ“Ž", description: "Attach files to external email domains" },
];

// â”€â”€ Policy Result State â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
interface PolicyResult {
    allowed: boolean;
    label: string;
    policyKey: string;
}

// â”€â”€ Time before "Prolonged Exposure" alert fires (ms) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const PROLONGED_THRESHOLD_MS = 7000;

export default function AttackerPage() {
    const [phase, setPhase] = useState<Phase>("idle");
    const [progress, setProgress] = useState(0);
    const [activeFile, setActiveFile] = useState<string | null>(null);
    const [stenoImageUrl, setStenoImageUrl] = useState<string | null>(null);
    const [users, setUsers] = useState<MockUser[]>([]);
    const [currentUser, setCurrentUser] = useState<MockUser | null>(null);
    const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);

    // â”€â”€ Fetch users from backend â”€â”€
    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const res = await fetch(API_ENDPOINTS.USERS); 
                const data = await res.json();
                if (data.users && data.users.length > 0) {
                    setUsers(data.users);
                    setCurrentUser(data.users[0]);
                }
            } catch (err) {
                console.error("Failed to fetch identities", err);
            }
        };
        fetchUsers();
    }, []);
    const [geofenceInfo, setGeofenceInfo] = useState<{ip: string, message: string} | null>(null);
    const [policyResult, setPolicyResult] = useState<PolicyResult | null>(null);
    const [policyLoading, setPolicyLoading] = useState<string | null>(null);
    const prolongedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    const normalFiles = [
        "Inventory_Q1.pdf",
        "Staff_Schedule.docx",
        "Store_Layout_V2.pdf",
        "Employee_Handbook.pdf",
        "Training_Video_Transcript.txt"
    ];
    const forbiddenFile = "Q4_Executive_Bonuses_2026.xlsx";
    const stenoFile = "Q4_Financial_Summary.png";
    const allFiles = [...normalFiles, forbiddenFile, stenoFile];

    // Build the structured log payload
    const buildLogPayload = (impactLevel: "MISTAKE" | "PROLONGED_EXPOSURE" | "EXFILTRATION") => ({
        impact_level: impactLevel,
        log_data: {
            timestamp: new Date().toISOString(),
            actor: {
                user_id: currentUser?.id ?? "UNKNOWN",
                department: currentUser?.department ?? "Unknown",
                mfa_status: "success"
            },
            action: {
                category: "Data",
                type: impactLevel === "EXFILTRATION" ? "file_download" : "file_view",
                status: "success"
            },
            resource: {
                name: forbiddenFile,
                volume_mb: 42.0,
                sensitivity_label: "PII_RESTRICTED"
            },
            context: {
                ip_address: "10.0.0.99",
                location: "Pune",
                device_type: "managed_laptop",
                edr_agent_active: true
            }
        }
    });

    const injectAlert = async (impactLevel: "MISTAKE" | "PROLONGED_EXPOSURE" | "EXFILTRATION") => {
        try {
            await fetch(API_ENDPOINTS.INJECT_LOG, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(buildLogPayload(impactLevel))
            });
        } catch {
            console.error("Connection to internal logging server failed.");
        }
    };

    // ——— Policy Action Handler —————————————————————————————————————————————————————————————————————
    const handlePolicyAction = async (action: PolicyAction) => {
        if (phase !== "idle" || !currentUser) return;
        setPolicyLoading(action.key);

        try {
            const res = await fetch(API_ENDPOINTS.POLICY_ACTION, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    user_id: currentUser?.id,
                    policy_key: action.key,
                    department: currentUser?.department,
                })
            });
            const data = await res.json();
            setPolicyResult({
                allowed: data.allowed,
                label: data.label || action.label,
                policyKey: action.key,
            });
            setPhase("policy_result");
        } catch {
            console.error("Policy check failed.");
        } finally {
            setPolicyLoading(null);
        }
    };

    const handleFileClick = async (fileName: string) => {
        // Normal files — skip geofence, no alert
        if (fileName !== forbiddenFile && fileName !== stenoFile) {
            setActiveFile(fileName);
            setPhase("opening");
            setTimeout(() => { setActiveFile(null); setPhase("idle"); }, 2000);
            return;
        }

        // ——— GEOFENCE CHECK: Only for classified files —————————————————————————————————————————
        try {
            const geoRes = await fetch(
                `http://localhost:8000/api/verify-network?user_id=${encodeURIComponent(currentUser?.id ?? "UNKNOWN")}`
            );
            const geoData = await geoRes.json();
            if (!geoData.allowed) {
                setGeofenceInfo({ ip: geoData.client_ip, message: geoData.message });
                setActiveFile(fileName);
                setPhase("geofenced");
                return;  // ← BLOCK HERE. File never opens.
            }
        } catch (e) {
            console.error("Geofence check failed", e);
            // Fail open for demo resilience — remove in production!
        }

        // ——— PHASE 1: Click detected 
        setActiveFile(fileName);
        
        if (fileName === stenoFile) {
            setPhase("opening");
            try {
                const formData = new FormData();
                formData.append("user_id", currentUser?.id ?? "UNKNOWN");        
                formData.append("department", currentUser?.department ?? "Unknown");
                
                let lat = "18.5204"; // Fallback to Pune coordinates for the hackathon demo
                let lng = "73.8567";
                if ("geolocation" in navigator) {
                    try {
                        const pos = await new Promise<GeolocationPosition>((resolve, reject) => {
                            navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 3000 });
                        });
                        lat = pos.coords.latitude.toFixed(4);
                        lng = pos.coords.longitude.toFixed(4);
                    } catch (e) {
                        console.warn("Geolocation failed or denied, using default Pune coordinates", e);
                    }
                }
                formData.append("lat", lat);
                formData.append("lng", lng);

                const res = await fetch("http://localhost:8000/api/download_watermarked", {
                    method: "POST",
                    body: formData
                });
                if (res.ok) {
                    const blob = await res.blob();
                    setStenoImageUrl(window.URL.createObjectURL(blob));
                }
            } catch (e) {
                 console.error("Failed to load steno image", e);
            }
            setPhase("viewing");
        } else {
            setPhase("viewing"); // Directly open the dummy document viewer
        }

        // Only the Excel file triggers the active Honey Trap SOC alerts
        if (fileName === forbiddenFile) {
            await injectAlert("MISTAKE");

            // ——— PHASE 3(b): Prolonged open timer ——————————————————————————————————————————————————
            prolongedTimerRef.current = setTimeout(async () => {
                await injectAlert("PROLONGED_EXPOSURE");
            }, PROLONGED_THRESHOLD_MS);
        }
    };

    const handleDownload = async () => {
        if (phase !== "viewing") return;
        if (prolongedTimerRef.current) clearTimeout(prolongedTimerRef.current);

        setPhase("downloading");
        setProgress(0);

        let current = 0;
        const interval = setInterval(async () => {
            current += 15;
            setProgress(Math.min(current, 100));
            if (current >= 100) {
                clearInterval(interval);
                setPhase("done");
                
                // If it's the specific steno file, download the URL we already fetched!
                if (activeFile === stenoFile && stenoImageUrl) {
                    try {
                        const a = document.createElement("a");
                        a.href = stenoImageUrl;
                        a.download = `STOLEN_${stenoFile}`;
                        document.body.appendChild(a);
                        a.click();
                    } catch (e) {
                         console.error("Steganography embedding download failed", e);
                    }
                } else if (activeFile === forbiddenFile) {
                    injectAlert("EXFILTRATION");
                }

                setTimeout(() => { setPhase("idle"); setActiveFile(null); }, 2000);
            }
        }, 300);
    };

    const handleClose = () => {
        if (prolongedTimerRef.current) clearTimeout(prolongedTimerRef.current);
        setPhase("idle");
        setActiveFile(null);
    };

    // Cleanup timer on unmount
    useEffect(() => {
        return () => { if (prolongedTimerRef.current) clearTimeout(prolongedTimerRef.current); };
    }, []);

    return (
        <div style={{ fontFamily: '"Courier New", Courier, monospace', backgroundColor: '#008080', minHeight: '100vh', padding: '40px' }}>
            
            <div style={{ backgroundColor: '#c0c0c0', border: '2px solid #808080', borderTop: '2px solid #dfdfdf', borderLeft: '2px solid #dfdfdf', width: '800px', margin: '0 auto', boxShadow: '2px 2px 0px #000' }}>
                
                {/* ——— Enterprise Session Header (Integrated) ——— */}
                <div style={{ 
                    borderBottom: '1px solid #808080',
                    backgroundColor: '#eee',
                    padding: '8px 15px', display: 'flex', alignItems: 'center', gap: '15px',
                    position: 'relative'
                }}>
                    <div style={{ fontSize: '11px', color: '#444', textTransform: 'uppercase', fontWeight: 'bold' }}>Session Login:</div>
                    <div style={{ fontWeight: 'bold', fontSize: '13px', color: '#000080', flex: 1 }}>
                        {currentUser?.name ?? "Loading..."} <span style={{ fontWeight: 'normal', color: '#666', fontSize: '11px' }}>— {currentUser?.id ?? ""}</span>
                    </div>
                    <button 
                        disabled={users.length === 0}
                        onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                        style={{ 
                            backgroundColor: '#c0c0c0', border: '1px solid #808080',
                            fontSize: '11px', padding: '4px 10px', cursor: users.length > 0 ? 'pointer' : 'default',
                            fontWeight: 'bold', boxShadow: '1px 1px 0px #fff inset',
                            opacity: users.length > 0 ? 1 : 0.5
                        }}>
                        Switch Identity ▼
                    </button>

                    {isUserMenuOpen && (
                        <div style={{
                            position: 'absolute', top: '100%', right: 15, marginTop: '2px',
                            backgroundColor: '#fff', border: '1px solid #808080',
                            boxShadow: '4px 4px 10px rgba(0,0,0,0.3)',
                            maxHeight: '300px', overflowY: 'auto', width: '250px',
                            zIndex: 1001
                        }}>
                            {users.map((user) => (
                                <div 
                                    key={user.id}
                                    onClick={() => { setCurrentUser(user); setIsUserMenuOpen(false); }}
                                    style={{
                                        padding: '8px 12px', borderBottom: '1px solid #eee',
                                        fontSize: '12px', cursor: 'pointer',
                                        backgroundColor: currentUser?.id === user.id ? '#000080' : 'white',
                                        color: currentUser?.id === user.id ? 'white' : 'black'
                                    }}>
                                    <div style={{ fontWeight: 'bold' }}>{user.name}</div>
                                    <div style={{ fontSize: '10px', opacity: 0.8 }}>{user.department}</div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                <div style={{ backgroundColor: '#000080', color: 'white', padding: '5px 10px', fontSize: '16px', fontWeight: 'bold' }}>
                    Williams-Sonoma Internal File Server
                </div>
                <div style={{ padding: '20px' }}>
                    <p style={{ fontSize: '14px', marginBottom: '20px', marginTop: 0 }}>Index of /corp/shared/confidential/</p>

                    <div style={{ backgroundColor: 'white', border: '2px solid #808080', borderBottom: '2px solid #dfdfdf', borderRight: '2px solid #dfdfdf', padding: '10px' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
                            <thead>
                                <tr style={{ borderBottom: '2px solid #808080', textAlign: 'left' }}>
                                    <th style={{ padding: '5px' }}>Name</th>
                                    <th style={{ padding: '5px' }}>Last Modified</th>
                                    <th style={{ padding: '5px' }}>Size</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr style={{ borderBottom: '1px dotted #ccc' }}>
                                    <td style={{ padding: '5px' }}><a href="#" style={{ color: '#0000ee' }}>../</a></td>
                                    <td style={{ padding: '5px' }}>-</td>
                                    <td style={{ padding: '5px' }}>-</td>
                                </tr>
                                {allFiles.map((file, idx) => (
                                    <tr key={idx} style={{ borderBottom: '1px dotted #ccc' }}>
                                        <td style={{ padding: '5px' }}>
                                            <a
                                                href="#"
                                                style={{ color: '#0000ee', textDecoration: 'underline' }}
                                                onClick={(e) => { e.preventDefault(); if (phase === "idle") handleFileClick(file); }}
                                            >
                                                {file}
                                            </a>
                                        </td>
                                        <td style={{ padding: '5px' }}>2026-04-0{(idx % 9) + 1} 14:00</td>
                                        <td style={{ padding: '5px' }}>{Math.floor((idx + 1) * 731 + 412)}K</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {/* ———————————————————————————————————————————————————————————————————————————————————————— */}
            {/*  DEVICE & POLICY ACTIONS PANEL (Windows 95 Style)               */}
            {/* ———————————————————————————————————————————————————————————————————————————————————————— */}
            <div style={{
                backgroundColor: '#c0c0c0',
                border: '2px solid #808080',
                borderTop: '2px solid #dfdfdf',
                borderLeft: '2px solid #dfdfdf',
                width: '800px',
                margin: '16px auto 0',
                boxShadow: '2px 2px 0px #000'
            }}>
                <div style={{
                    backgroundColor: '#000080',
                    color: 'white',
                    padding: '5px 10px',
                    fontSize: '14px',
                    fontWeight: 'bold',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                }}>
                    <span>🛡️</span> Device &amp; Policy Actions
                    <span style={{ flex: 1 }} />
                    <span style={{ fontSize: '10px', fontWeight: 'normal', opacity: 0.8 }}>
                        User: {currentUser?.id ?? "None"}
                    </span>
                </div>

                <div style={{ padding: '16px 20px' }}>
                    <p style={{ fontSize: '11px', color: '#444', margin: '0 0 14px 0' }}>
                        Simulate device &amp; policy actions as the current user. Actions are checked against the IAM Privilege Control page.
                    </p>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                        {POLICY_ACTIONS.map((action) => {
                            const isLoading = policyLoading === action.key;
                            return (
                                <button
                                    key={action.key}
                                    disabled={phase !== "idle" || isLoading}
                                    onClick={() => handlePolicyAction(action)}
                                    style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '12px',
                                        padding: '12px 14px',
                                        backgroundColor: isLoading ? '#d4d0c8' : '#c0c0c0',
                                        border: '2px solid #808080',
                                        borderTop: '2px solid #dfdfdf',
                                        borderLeft: '2px solid #dfdfdf',
                                        cursor: phase === "idle" && !isLoading ? 'pointer' : 'default',
                                        fontFamily: '"Courier New", Courier, monospace',
                                        fontSize: '13px',
                                        textAlign: 'left',
                                        boxShadow: isLoading ? 'none' : '1px 1px 0px #fff inset',
                                        opacity: phase !== "idle" && !isLoading ? 0.5 : 1,
                                        transition: 'all 0.1s',
                                    }}
                                    onMouseDown={(e) => {
                                        if (phase === "idle" && !isLoading) {
                                            (e.currentTarget as HTMLButtonElement).style.borderTop = '2px solid #808080';
                                            (e.currentTarget as HTMLButtonElement).style.borderLeft = '2px solid #808080';
                                            (e.currentTarget as HTMLButtonElement).style.borderBottom = '2px solid #dfdfdf';
                                            (e.currentTarget as HTMLButtonElement).style.borderRight = '2px solid #dfdfdf';
                                            (e.currentTarget as HTMLButtonElement).style.boxShadow = 'none';
                                        }
                                    }}
                                    onMouseUp={(e) => {
                                        (e.currentTarget as HTMLButtonElement).style.borderTop = '2px solid #dfdfdf';
                                        (e.currentTarget as HTMLButtonElement).style.borderLeft = '2px solid #dfdfdf';
                                        (e.currentTarget as HTMLButtonElement).style.borderBottom = '2px solid #808080';
                                        (e.currentTarget as HTMLButtonElement).style.borderRight = '2px solid #808080';
                                        (e.currentTarget as HTMLButtonElement).style.boxShadow = '1px 1px 0px #fff inset';
                                    }}
                                    onMouseLeave={(e) => {
                                        (e.currentTarget as HTMLButtonElement).style.borderTop = '2px solid #dfdfdf';
                                        (e.currentTarget as HTMLButtonElement).style.borderLeft = '2px solid #dfdfdf';
                                        (e.currentTarget as HTMLButtonElement).style.borderBottom = '2px solid #808080';
                                        (e.currentTarget as HTMLButtonElement).style.borderRight = '2px solid #808080';
                                        (e.currentTarget as HTMLButtonElement).style.boxShadow = '1px 1px 0px #fff inset';
                                    }}
                                >
                                    <span style={{ fontSize: '24px', lineHeight: 1 }}>{action.icon}</span>
                                    <div>
                                        <div style={{ fontWeight: 'bold', color: '#000', marginBottom: '2px' }}>
                                            {isLoading ? 'Checking...' : action.label}
                                        </div>
                                        <div style={{ fontSize: '10px', color: '#666' }}>
                                            {action.description}
                                        </div>
                                    </div>
                                </button>
                            );
                        })}
                    </div>
                </div>

                {/* Status Bar */}
                <div style={{
                    borderTop: '1px solid #808080',
                    padding: '4px 10px',
                    fontSize: '10px',
                    color: '#555',
                    backgroundColor: '#d4d0c8',
                    display: 'flex',
                    gap: '20px'
                }}>
                    <span>Policy Engine: Connected</span>
                    <span>|</span>
                    <span>Active Session: {currentUser?.id ?? "None"}</span>
                    <span>|</span>
                    <span>{currentUser?.department ?? "Not Loaded"}</span>
                </div>
            </div>

            {/* ——— OVERLAY: Policy Action Result ——— */}
            {phase === "policy_result" && policyResult && (
                <div style={{
                    position: 'fixed', inset: 0,
                    backgroundColor: 'rgba(0,0,0,0.75)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    zIndex: 9999
                }}>
                    <div style={{
                        width: '480px',
                        background: policyResult.allowed ? '#0a0a0a' : '#0a0a0a',
                        border: `2px solid ${policyResult.allowed ? '#00aa44' : '#cc0000'}`,
                        boxShadow: `0 0 40px ${policyResult.allowed ? 'rgba(0,170,68,0.4)' : 'rgba(204,0,0,0.5)'}`,
                        fontFamily: 'Courier New, monospace',
                        overflow: 'hidden'
                    }}>
                        {/* Header */}
                        <div style={{
                            backgroundColor: policyResult.allowed ? '#00663d' : '#cc0000',
                            padding: '10px 16px',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '10px'
                        }}>
                            <span style={{ fontSize: '18px' }}>{policyResult.allowed ? '✅' : '🛡️'}</span>
                            <span style={{
                                color: 'white',
                                fontWeight: 'bold',
                                fontSize: '13px',
                                letterSpacing: '0.15em',
                                textTransform: 'uppercase'
                            }}>
                                {policyResult.allowed ? 'AEGIS Policy — Action Permitted' : 'AEGIS Policy — Access Denied'}
                            </span>
                        </div>

                        {/* Big icon */}
                        <div style={{ padding: '25px', textAlign: 'center', borderBottom: '1px solid #333' }}>
                            <div style={{ fontSize: '56px', marginBottom: '10px' }}>
                                {policyResult.allowed ? '🔓' : '🚫'}
                            </div>
                            <div style={{
                                color: policyResult.allowed ? '#00cc66' : '#ff3333',
                                fontSize: '20px',
                                fontWeight: 'bold',
                                letterSpacing: '0.2em',
                                marginBottom: '6px'
                            }}>
                                {policyResult.allowed ? 'ACTION AUTHORIZED' : 'POLICY VIOLATION'}
                            </div>
                            <div style={{ color: '#888', fontSize: '12px', letterSpacing: '0.1em' }}>
                                {policyResult.label.toUpperCase()}
                            </div>
                        </div>

                        {/* Details */}
                        <div style={{ padding: '20px 24px', display: 'grid', gap: '10px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1a1a1a', paddingBottom: '8px' }}>
                                <span style={{ color: '#555', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>User Identity</span>
                                <span style={{ color: '#ff9900', fontSize: '12px', fontWeight: 'bold' }}>{currentUser?.id ?? "UNKNOWN"} — {currentUser?.name ?? "No Name"}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1a1a1a', paddingBottom: '8px' }}>
                                <span style={{ color: '#555', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Policy Key</span>
                                <span style={{ color: '#aaa', fontSize: '12px', fontWeight: 'bold', fontFamily: 'monospace' }}>{policyResult.policyKey}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1a1a1a', paddingBottom: '8px' }}>
                                <span style={{ color: '#555', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>IAM Decision</span>
                                <span style={{
                                    color: policyResult.allowed ? '#00cc66' : '#ff3333',
                                    fontSize: '12px',
                                    fontWeight: 'bold'
                                }}>
                                    {policyResult.allowed ? '✓ PERMITTED' : '✗ DENIED — NOT IN PROFILE'}
                                </span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <span style={{ color: '#555', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>SOC Alert Status</span>
                                <span style={{
                                    color: policyResult.allowed ? '#555' : '#cc00ff',
                                    fontSize: '12px',
                                    fontWeight: 'bold'
                                }}>
                                    {policyResult.allowed ? '— No alert generated' : '⚡ VIOLATION BROADCAST SENT'}
                                </span>
                            </div>
                        </div>

                        {/* Footer */}
                        <div style={{ padding: '10px 24px 20px' }}>
                            <div style={{
                                backgroundColor: policyResult.allowed ? '#001a0d' : '#1a0000',
                                border: `1px solid ${policyResult.allowed ? '#004400' : '#440000'}`,
                                padding: '10px 14px',
                                fontSize: '11px',
                                color: policyResult.allowed ? '#66cc88' : '#ff6666',
                                marginBottom: '16px',
                                lineHeight: 1.5
                            }}>
                                {policyResult.allowed
                                    ? `ℹ This action was authorized by the IAM profile for ${currentUser?.id ?? "this user"}. Activity logged for audit trail.`
                                    : `⚠ This policy violation has been logged and reported to the Security Operations Center. The user's access profile does not include this privilege.`
                                }
                            </div>
                            <button
                                onClick={() => { setPhase('idle'); setPolicyResult(null); }}
                                style={{
                                    width: '100%',
                                    backgroundColor: '#1a1a1a',
                                    border: '1px solid #444',
                                    color: '#888',
                                    padding: '10px',
                                    cursor: 'pointer',
                                    fontSize: '12px',
                                    letterSpacing: '0.1em',
                                    textTransform: 'uppercase'
                                }}
                            >
                                Acknowledge &amp; Dismiss
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* ——— OVERLAY: Geofence Denied ——— */}
            {phase === "geofenced" && (
                <div style={{
                    position: 'fixed', inset: 0,
                    backgroundColor: 'rgba(0,0,0,0.75)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    zIndex: 9999
                }}>
                    <div style={{
                        width: '520px',
                        background: '#0a0a0a',
                        border: '2px solid #cc0000',
                        boxShadow: '0 0 40px rgba(204,0,0,0.5)',
                        fontFamily: 'Courier New, monospace',
                        overflow: 'hidden'
                    }}>
                        {/* Header */}
                        <div style={{ backgroundColor: '#cc0000', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <span style={{ fontSize: '18px' }}>ðŸ›¡ï¸</span>
                            <span style={{ color: 'white', fontWeight: 'bold', fontSize: '13px', letterSpacing: '0.15em', textTransform: 'uppercase' }}>
                                AEGIS Network Perimeter â€” Access Denied
                            </span>
                        </div>

                        {/* Big warning */}
                        <div style={{ padding: '30px', textAlign: 'center', borderBottom: '1px solid #333' }}>
                            <div style={{ fontSize: '56px', marginBottom: '10px' }}>ðŸš«</div>
                            <div style={{ color: '#ff3333', fontSize: '20px', fontWeight: 'bold', letterSpacing: '0.2em', marginBottom: '6px' }}>
                                GEOFENCE VIOLATION
                            </div>
                            <div style={{ color: '#888', fontSize: '12px', letterSpacing: '0.1em' }}>
                                CLASSIFIED DOCUMENT ACCESS BLOCKED
                            </div>
                        </div>

                        {/* Details grid */}
                        <div style={{ padding: '20px 24px', display: 'grid', gap: '12px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1a1a1a', paddingBottom: '8px' }}>
                                <span style={{ color: '#555', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>User Identity</span>
                                <span style={{ color: '#ff9900', fontSize: '12px', fontWeight: 'bold' }}>{currentUser?.id ?? "UNKNOWN"} — {currentUser?.name ?? "No Name"}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1a1a1a', paddingBottom: '8px' }}>
                                <span style={{ color: '#555', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Source IP Address</span>
                                <span style={{ color: '#ff3333', fontSize: '12px', fontWeight: 'bold' }}>{geofenceInfo?.ip ?? 'Unknown'}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1a1a1a', paddingBottom: '8px' }}>
                                <span style={{ color: '#555', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Allowed Subnet</span>
                                <span style={{ color: '#00cc66', fontSize: '12px', fontWeight: 'bold' }}>192.168.1.x (Office WiFi Only)</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1a1a1a', paddingBottom: '8px' }}>
                                <span style={{ color: '#555', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Document Requested</span>
                                <span style={{ color: '#aaa', fontSize: '12px' }}>{activeFile}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <span style={{ color: '#555', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>SOC Alert Status</span>
                                <span style={{ color: '#cc00ff', fontSize: '12px', fontWeight: 'bold' }}>âš¡ BROADCAST SENT</span>
                            </div>
                        </div>

                        {/* Footer */}
                        <div style={{ padding: '10px 24px 20px' }}>
                            <div style={{ backgroundColor: '#1a0000', border: '1px solid #440000', padding: '10px 14px', fontSize: '11px', color: '#ff6666', marginBottom: '16px', lineHeight: 1.5 }}>
                                âš  This access attempt has been logged and reported to the Security Operations Center. Connect to the approved office WiFi network (192.168.1.x) to access classified documents.
                            </div>
                            <button
                                onClick={() => { setPhase('idle'); setActiveFile(null); setGeofenceInfo(null); }}
                                style={{ width: '100%', backgroundColor: '#1a1a1a', border: '1px solid #444', color: '#888', padding: '10px', cursor: 'pointer', fontSize: '12px', letterSpacing: '0.1em', textTransform: 'uppercase' }}
                            >
                                Acknowledge &amp; Dismiss
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* â”€â”€ OVERLAY: Opening Normal File â”€â”€ */}
            {phase === "opening" && activeFile && activeFile !== forbiddenFile && (

                <div style={{
                    position: 'fixed', top: '50%', left: '50%',
                    transform: 'translate(-50%, -50%)',
                    width: '320px',
                    backgroundColor: '#c0c0c0',
                    border: '2px solid #808080',
                    borderTop: '2px solid #dfdfdf',
                    borderLeft: '2px solid #dfdfdf',
                    boxShadow: '4px 4px 0px rgba(0,0,0,0.5)',
                    padding: '0',
                    zIndex: 9999
                }}>
                    <div style={{ backgroundColor: '#000080', color: 'white', padding: '5px 10px', fontWeight: 'bold' }}>
                        Opening File...
                    </div>
                    <div style={{ padding: '20px', textAlign: 'center' }}>
                        <p style={{ margin: 0, fontSize: '14px' }}>Retrieving {activeFile}â€¦</p>
                    </div>
                </div>
            )}

            {/* â”€â”€ OVERLAY: Viewing Confidential File (Dummy Spreadsheet) â”€â”€ */}
            {phase === "viewing" && activeFile === forbiddenFile && (
                <div style={{
                    position: 'fixed', top: '50%', left: '50%',
                    transform: 'translate(-50%, -50%)',
                    width: '850px',
                    backgroundColor: '#f3f2f1',
                    border: '1px solid #ccc',
                    boxShadow: '0 10px 25px rgba(0,0,0,0.2)',
                    padding: '0',
                    zIndex: 9999,
                    fontFamily: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif'
                }}>
                    <div style={{ backgroundColor: '#107c41', color: 'white', padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ fontWeight: 'bold', fontSize: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ backgroundColor: 'white', color: '#107c41', padding: '2px 6px', borderRadius: '3px', fontWeight: 'bold' }}>X</span>
                            {activeFile} - Excel Online
                        </div>
                        <button onClick={handleClose} style={{ background: 'transparent', border: 'none', color: 'white', fontSize: '16px', cursor: 'pointer' }}>âœ–</button>
                    </div>

                    <div style={{ backgroundColor: '#f3f2f1', padding: '8px 12px', borderBottom: '1px solid #e1dfdd', display: 'flex', gap: '15px', alignItems: 'center' }}>
                        <button style={{ border: 'none', background: 'transparent', padding: '4px 8px', cursor: 'pointer', fontSize: '12px' }}>File</button>
                        <button style={{ border: 'none', background: '#eaeaea', padding: '4px 8px', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold' }}>Home</button>
                        <button style={{ border: 'none', background: 'transparent', padding: '4px 8px', cursor: 'pointer', fontSize: '12px' }}>Insert</button>
                        <div style={{ flex: 1 }}></div>
                        <button onClick={handleDownload} style={{ background: '#107c41', color: 'white', border: 'none', padding: '6px 12px', borderRadius: '2px', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold' }}>
                            â¤“ Download Copy
                        </button>
                    </div>

                    <div style={{ backgroundColor: '#fff4ce', color: '#794e00', padding: '6px 12px', fontSize: '12px', borderBottom: '1px solid #e1dfdd', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span>âš </span> <strong>CONFIDENTIAL:</strong> This document contains highly sensitive Executive Compensation data. Do not distribute.
                    </div>

                    <div style={{ padding: '20px', backgroundColor: 'white', height: '400px', overflowY: 'auto' }}>
                        <h2 style={{ marginTop: 0, color: '#333', borderBottom: '2px solid #107c41', paddingBottom: '10px' }}>2026 Executive Bonus Pool Allocation (Q4 Draft)</h2>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', marginTop: '15px' }}>
                            <thead>
                                <tr style={{ backgroundColor: '#f3f2f1', borderBottom: '2px solid #ccc', textAlign: 'left' }}>
                                    <th style={{ padding: '8px', border: '1px solid #e1dfdd' }}>Executive Name</th>
                                    <th style={{ padding: '8px', border: '1px solid #e1dfdd' }}>Role / Region</th>
                                    <th style={{ padding: '8px', border: '1px solid #e1dfdd' }}>Base Salary</th>
                                    <th style={{ padding: '8px', border: '1px solid #e1dfdd', backgroundColor: '#eef2ed' }}>Target Bonus %</th>
                                    <th style={{ padding: '8px', border: '1px solid #e1dfdd', backgroundColor: '#eef2ed', fontWeight: 'bold', color: '#107c41' }}>Approved Q4 Bonus</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd', fontWeight: 'bold' }}>Alber, Laura</td>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd' }}>CEO</td>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd' }}>$1,500,000</td>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd', backgroundColor: '#f9f9f9', textAlign: 'center' }}>200%</td>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd', backgroundColor: '#eaf4eb', fontWeight: 'bold', color: '#107c41' }}>$3,450,000</td>
                                </tr>
                                <tr>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd', fontWeight: 'bold' }}>Hayes, Jeff</td>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd' }}>CFO</td>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd' }}>$850,000</td>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd', backgroundColor: '#f9f9f9', textAlign: 'center' }}>150%</td>
                                    <td style={{ padding: '8px', border: '1px solid #e1dfdd', backgroundColor: '#eaf4eb', fontWeight: 'bold', color: '#107c41' }}>$1,275,000</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* â”€â”€ OVERLAY: Viewing Confidential Image (Steno File) â”€â”€ */}
            {phase === "viewing" && activeFile === stenoFile && (
                <div style={{
                    position: 'fixed', top: '50%', left: '50%',
                    transform: 'translate(-50%, -50%)',
                    width: '850px',
                    height: '600px',
                    backgroundColor: '#1E1E1E',
                    border: '1px solid #444',
                    boxShadow: '0 10px 40px rgba(0,0,0,0.5)',
                    padding: '0',
                    zIndex: 9999,
                    fontFamily: 'Segoe UI, sans-serif',
                    display: 'flex',
                    flexDirection: 'column'
                }}>
                    {/* Fake App Header */}
                    <div style={{ backgroundColor: '#2D2D2D', color: 'white', padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ fontWeight: 'bold', fontSize: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ color: '#61A3DD', fontWeight: 'bold' }}>ðŸ–¼ï¸</span>
                            {activeFile} - Image Viewer
                        </div>
                        <button onClick={handleClose} style={{ background: 'transparent', border: 'none', color: 'white', fontSize: '16px', cursor: 'pointer' }}>âœ–</button>
                    </div>

                    {/* Toolbar */}
                    <div style={{ backgroundColor: '#252526', padding: '8px 12px', borderBottom: '1px solid #333', display: 'flex', gap: '15px', alignItems: 'center' }}>
                        <div style={{ flex: 1 }}></div>
                        <button onClick={handleDownload} style={{ background: '#007ACC', color: 'white', border: 'none', padding: '6px 12px', borderRadius: '2px', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold' }}>
                            â¤“ Download Original
                        </button>
                    </div>

                    {/* Image Render */}
                    <div style={{ flex: 1, backgroundColor: '#111', padding: '20px', display: 'flex', justifyContent: 'center', alignItems: 'center', overflow: 'auto' }}>
                        {stenoImageUrl ? (
                            <img src={stenoImageUrl} alt="Confidential" style={{ display: 'block', boxShadow: '0 0 20px rgba(0,0,0,0.5)', width: '800px', height: '600px', flexShrink: 0 }} />
                        ) : (
                            <div style={{ color: '#666' }}>Loading high-resolution asset...</div>
                        )}
                    </div>
                </div>
            )}

            {/* â”€â”€ OVERLAY: Downloading â”€â”€ */}
            {(phase === "downloading" || phase === "done") && (activeFile === forbiddenFile || activeFile === stenoFile) && (
                <div style={{
                    position: 'fixed', top: '50%', left: '50%',
                    transform: 'translate(-50%, -50%)',
                    width: '350px',
                    backgroundColor: '#f3f2f1',
                    border: '1px solid #ccc',
                    boxShadow: '0 10px 25px rgba(0,0,0,0.2)',
                    padding: '20px',
                    zIndex: 10000,
                    fontFamily: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif'
                }}>
                    <h3 style={{ marginTop: 0, fontSize: '16px', color: '#333' }}>Downloading File</h3>
                    <p style={{ margin: '0 0 15px 0', fontSize: '13px', color: '#555' }}>Saving: {activeFile}</p>
                    {phase === "downloading" ? (
                        <p style={{ fontSize: '12px', color: '#888', marginBottom: '5px' }}>
                            Estimated time left: 00:00:0{Math.max(0, Math.floor((100 - progress) / 30))}s
                        </p>
                    ) : (
                         <p style={{ fontSize: '12px', color: '#107c41', marginBottom: '5px', fontWeight: 'bold' }}>
                            Download complete.
                        </p>
                    )}
                    <div style={{ width: '100%', backgroundColor: '#e1dfdd', height: '8px', borderRadius: '4px', overflow: 'hidden' }}>
                        <div style={{ width: `${phase === "done" ? 100 : progress}%`, backgroundColor: '#107c41', height: '100%', transition: 'width 0.3s' }} />
                    </div>
                </div>
            )}
        </div>
    );
}
