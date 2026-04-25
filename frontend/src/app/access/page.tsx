"use client";

import React, { useState, useEffect } from 'react';
import { Shield, ChevronRight, Check } from "lucide-react";
import { cn } from "@/lib/utils";

// Dummy predefined permissions
const MASTER_PERMISSIONS = [
  // Existing App Access
  "Software_Dev",
  "Marketing_Db",
  "logistics_portal",
  "employee_schedule_db",
  "timekeeper_app",
  "wms_scanner",
  "inventory_db",
  "payroll_db",
  "sales_analytics_db",
  "pos_terminal",
  "admin_console",
  
  // New Security & Device Policies
  "EXTERNAL_STORAGE_ALLOWED",     // e.g., USB / Pen Drives
  "EXTERNAL_EMAIL_ATTACHMENTS",   // e.g., Attaching files to non-company domains
  "SOFTWARE_INSTALLATION",        // e.g., Downloading and installing unapproved software
  "UNRESTRICTED_WEB_BROWSING",    // e.g., Bypassing the corporate web filter
];

interface User {
  id: string;
  department: string;
  permissions: string[];
}

export default function AccessPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [tempPermissions, setTempPermissions] = useState<string[]>([]);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/users");
      const data = await res.json();
      setUsers(data.users || []);
    } catch (e) {
      console.error("Failed to fetch users", e);
    } finally {
      setLoading(false);
    }
  };

  const openEditor = (user: User) => {
    setEditingUser(user);
    setTempPermissions([...user.permissions]);
  };

  const togglePermission = (perm: string) => {
    if (tempPermissions.includes(perm)) {
      setTempPermissions(tempPermissions.filter(p => p !== perm));
    } else {
      setTempPermissions([...tempPermissions, perm]);
    }
  };

  const savePermissions = async () => {
    if (!editingUser) return;
    setUpdating(true);
    try {
      await fetch("http://localhost:8000/api/users/permissions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id: editingUser.id,
          permissions: tempPermissions
        })
      });
      // Update local state
      setUsers(users.map(u => u.id === editingUser.id ? { ...u, permissions: tempPermissions } : u));
      setEditingUser(null);
    } catch (e) {
      console.error("Failed to save permissions", e);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="space-y-8 pb-32">
      <header className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <p className="text-[10px] font-heading font-bold uppercase tracking-[0.2em] text-slate-500 mb-1">
            Identity & Access Management
          </p>
          <h2 className="text-3xl font-extrabold font-heading tracking-tight text-slate-100 flex items-center gap-3">
            <Shield className="h-8 w-8 text-primary" />
            Privilege Control
          </h2>
        </div>
      </header>

      {/* Main Table */}
      <div className="glass-panel overflow-hidden border border-white/5 bg-card/40 rounded-sm">
        {loading ? (
          <div className="p-8 text-center text-slate-500">Loading directory...</div>
        ) : (
          <table className="w-full text-left">
            <thead>
              <tr className="bg-white/[0.01] text-[10px] uppercase tracking-widest text-slate-500 font-bold border-b border-white/5">
                <th className="px-6 py-4">Employee ID</th>
                <th className="px-6 py-4">Department</th>
                <th className="px-6 py-4">Assigned Resources</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.02]">
              {users.map((user) => (
                <tr key={user.id} className="hover:bg-slate-800/20 transition-colors">
                  <td className="px-6 py-4">
                    <p className="text-sm font-bold text-slate-200">{user.id}</p>
                  </td>
                  <td className="px-6 py-4 text-xs font-medium text-slate-500">{user.department}</td>
                  <td className="px-6 py-4">
                    <div className="flex flex-wrap gap-2">
                      {user.permissions.length === 0 && <span className="text-xs text-slate-600">No access</span>}
                      {user.permissions.map(p => (
                        <span key={p} className="text-[9px] font-bold px-2 py-0.5 rounded-sm bg-primary/10 text-primary border border-primary/20 uppercase tracking-widest">
                          {p}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button 
                      onClick={() => openEditor(user)}
                      className="text-[10px] font-bold uppercase tracking-widest text-slate-400 hover:text-white px-3 py-1 bg-white/5 hover:bg-white/10 rounded-sm transition-all"
                    >
                      Manage
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Edit Modal */}
      {editingUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-[500px] glass-panel bg-[#141A23] border border-white/10 shadow-2xl rounded-sm p-6">
            <h3 className="text-lg font-bold text-white mb-1">Edit Permissions</h3>
            <p className="text-xs text-slate-400 mb-6 font-mono">Target: {editingUser.id} ({editingUser.department})</p>

            <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
              {MASTER_PERMISSIONS.map(perm => {
                const isActive = tempPermissions.includes(perm);
                return (
                  <div 
                    key={perm} 
                    onClick={() => togglePermission(perm)}
                    className={cn(
                      "flex items-center gap-3 p-3 border rounded-sm cursor-pointer transition-all",
                      isActive ? "bg-primary/5 border-primary/30" : "bg-white/[0.02] border-white/5 hover:bg-white/5"
                    )}
                  >
                    <div className={cn(
                      "w-4 h-4 border rounded-sm flex items-center justify-center",
                      isActive ? "bg-primary border-primary" : "border-slate-600"
                    )}>
                      {isActive && <Check className="w-3 h-3 text-black" />}
                    </div>
                    <div>
                      <p className={cn("text-xs font-bold uppercase tracking-widest", isActive ? "text-slate-200" : "text-slate-500")}>
                        {perm}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="flex justify-end gap-3 mt-6 pt-6 border-t border-white/5">
              <button 
                onClick={() => setEditingUser(null)}
                className="px-4 py-2 text-xs font-bold uppercase tracking-widest text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button 
                onClick={savePermissions}
                disabled={updating}
                className="px-4 py-2 text-xs font-bold uppercase tracking-widest bg-emerald-600/20 text-emerald-500 border border-emerald-500/30 hover:bg-emerald-600/30 transition-all rounded-sm disabled:opacity-50"
              >
                {updating ? 'Saving...' : 'Save Policy'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
