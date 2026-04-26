"use client";

import React, { useState, useRef } from 'react';
import { Shield, UploadCloud, Download, Loader2, Fingerprint } from "lucide-react";
import { cn } from "@/lib/utils";

export default function EncoderPage() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [status, setStatus] = useState<'idle' | 'baking' | 'success' | 'error'>('idle');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [watermarkedUrl, setWatermarkedUrl] = useState<string | null>(null);
  
  // Form fields
  const [empId, setEmpId] = useState("emp_101");
  const [dept, setDept] = useState("Executive");

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (selectedFile: File) => {
    setFile(selectedFile);
    setPreview(URL.createObjectURL(selectedFile));
    setStatus('idle');
    setWatermarkedUrl(null);
    setErrorMsg(null);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const runEncoder = async () => {
    if (!file || !empId) return;
    
    setStatus('baking');
    const formData = new FormData();
    formData.append("file", file);
    formData.append("user_id", empId);
    formData.append("department", dept);
    
    // Add dummy location or fetch real
    formData.append("lat", "18.5204");
    formData.append("lng", "73.8567");

    try {
      const res = await fetch("http://localhost:8000/api/download_watermarked", {
        method: "POST",
        body: formData
      });
      
      if (!res.ok) {
        throw new Error("Failed to encode document");
      }
      
      const blob = await res.blob();
      setWatermarkedUrl(window.URL.createObjectURL(blob));
      setStatus('success');
    } catch (e: any) {
      console.error(e);
      setErrorMsg(e.message || "System Offline");
      setStatus('error');
    }
  };

  return (
    <div className="space-y-8 pb-32">
      <header className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <p className="text-[10px] font-heading font-bold uppercase tracking-[0.2em] text-slate-500 mb-1">
            Company Admin Panel
          </p>
          <h2 className="text-3xl font-extrabold font-heading tracking-tight text-slate-100 flex items-center gap-3">
            <Shield className="h-8 w-8 text-blue-500" />
            The Invisible Bake (Encoder)
          </h2>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Input Zone */}
        <div className="glass-panel p-6 border border-white/5 rounded-sm flex flex-col gap-6">
          
          <div className="space-y-4">
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-2 block">Employee ID to Encode</label>
              <input 
                type="text" 
                value={empId}
                onChange={(e) => setEmpId(e.target.value)}
                className="w-full bg-black/40 border border-slate-700 rounded px-4 py-2 text-white font-mono"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-2 block">Department</label>
              <input 
                type="text" 
                value={dept}
                onChange={(e) => setDept(e.target.value)}
                className="w-full bg-black/40 border border-slate-700 rounded px-4 py-2 text-white font-mono"
              />
            </div>
          </div>

          <div>
             <h3 className="text-sm font-bold text-slate-300 uppercase tracking-widest mb-4 border-b border-white/10 pb-2 flex items-center gap-2">
               <UploadCloud className="w-4 h-4" /> Source Document
             </h3>
             <div 
               className={cn(
                 "border-2 border-dashed rounded-sm flex flex-col items-center justify-center p-8 transition-colors cursor-pointer",
                 isDragging ? "border-blue-500 bg-blue-500/10" : "border-slate-700 bg-slate-900/50 hover:bg-slate-800/50"
               )}
               onDragOver={handleDragOver}
               onDragLeave={handleDragLeave}
               onDrop={handleDrop}
               onClick={() => fileInputRef.current?.click()}
             >
               <input 
                 type="file" 
                 ref={fileInputRef} 
                 className="hidden" 
                 accept="image/*"
                 onChange={(e) => {
                   if (e.target.files && e.target.files[0]) {
                     handleFileSelect(e.target.files[0]);
                   }
                 }}
               />
               <UploadCloud className={cn("w-12 h-12 mb-4", isDragging ? "text-blue-500" : "text-slate-500")} />
               <p className="text-slate-300 font-medium mb-1">Drop clean image here or click to browse</p>
               <p className="text-slate-500 text-xs">Supports PNG, JPG</p>
             </div>
          </div>

          <button
            onClick={runEncoder}
            disabled={!file || status === 'baking'}
            className="w-full py-4 px-6 rounded-sm font-bold uppercase tracking-widest transition-all relative overflow-hidden disabled:opacity-50 disabled:cursor-not-allowed bg-blue-600 hover:bg-blue-500 text-white"
          >
            {status === 'baking' ? (
              <span className="flex items-center justify-center gap-2">
                <Loader2 className="w-5 h-5 animate-spin" />
                Baking Stealth QR...
              </span>
            ) : (
              <span className="flex items-center justify-center gap-2">
                <Fingerprint className="w-5 h-5" />
                Apply Invisible Watermark
              </span>
            )}
          </button>
        </div>

        {/* Output Zone */}
        <div className="glass-panel p-6 border border-white/5 rounded-sm flex flex-col">
          <h3 className="text-sm font-bold text-slate-300 uppercase tracking-widest mb-4 border-b border-white/10 pb-2">
            Output Preview
          </h3>
          
          <div className="flex-1 bg-black/50 border border-white/5 rounded-sm flex items-center justify-center overflow-hidden relative min-h-[300px]">
            {status === 'success' && watermarkedUrl ? (
              <div className="absolute inset-0 flex flex-col">
                <div className="flex-1 overflow-auto p-4 flex items-center justify-center">
                   <img src={watermarkedUrl} alt="Secured Document" className="max-w-full max-h-full object-contain" />
                </div>
                <div className="bg-blue-950/40 border-t border-blue-500/30 p-4 flex justify-between items-center">
                  <p className="text-blue-400 text-xs font-mono uppercase tracking-widest">
                    Digital DNA Injected Successfully
                  </p>
                  <a 
                    href={watermarkedUrl} 
                    download={`Secured_${empId}.png`}
                    className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded text-xs font-bold uppercase tracking-widest transition-colors"
                  >
                    <Download className="w-4 h-4" /> Download SECURED DOC
                  </a>
                </div>
              </div>
            ) : preview ? (
               <img src={preview} alt="Clean Document" className="max-w-full max-h-full object-contain opacity-50 grayscale" />
            ) : (
              <div className="text-center text-slate-600 space-y-3">
                <Shield className="w-16 h-16 mx-auto opacity-20" />
                <p className="font-mono text-sm uppercase tracking-widest">Awaiting source image</p>
              </div>
            )}
            
            {status === 'baking' && (
              <div className="absolute inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center">
                <div className="text-center space-y-4">
                  <div className="w-16 h-16 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mx-auto"></div>
                  <p className="text-blue-400 font-mono text-xs uppercase tracking-widest animate-pulse">
                    Injecting Frequency Domain Signature...
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
