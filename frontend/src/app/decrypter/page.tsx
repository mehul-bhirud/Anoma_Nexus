"use client";

import React, { useState, useRef } from 'react';
import { Fingerprint, UploadCloud, AlertTriangle, ShieldCheck, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

export default function DecrypterPage() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [status, setStatus] = useState<'idle' | 'analyzing' | 'success' | 'error'>('idle');
  const [result, setResult] = useState<string | null>(null);
  const [isAnalogRecovery, setIsAnalogRecovery] = useState(false);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (selectedFile: File) => {
    setFile(selectedFile);
    setPreview(URL.createObjectURL(selectedFile));
    setStatus('idle');
    setResult(null);
    setIsAnalogRecovery(false);
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

  const runForensics = async () => {
    if (!file) return;
    
    setStatus('analyzing');
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("http://localhost:8000/api/extract_watermark", {
        method: "POST",
        body: formData
      });
      const data = await res.json();
      
      if (data.extracted_signature && !data.error) {
        // Assume signature comes padded with '*' like "ID:M.NAGAR|DPT:DevOps|T:1738**"
        const cleanSig = data.extracted_signature.replace(/\*/g, '');
        setResult(cleanSig);
        setIsAnalogRecovery(!!data.analog_recovery);
        setStatus('success');
      } else {
        setResult(data.error || "Failed to extract discrete frequencies");
        setStatus('error');
      }
    } catch (e) {
      console.error(e);
      setResult("System Offline or Extraction Failed");
      setStatus('error');
    }
  };

  return (
    <div className="space-y-8 pb-32">
      <header className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <p className="text-[10px] font-heading font-bold uppercase tracking-[0.2em] text-slate-500 mb-1">
            Forensic Intelligence
          </p>
          <h2 className="text-3xl font-extrabold font-heading tracking-tight text-slate-100 flex items-center gap-3">
            <Fingerprint className="h-8 w-8 text-rose-500" />
            Image Steganography Decrypter
          </h2>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Upload Zone */}
        <div className="glass-panel p-6 border border-white/5 rounded-sm flex flex-col">
          <h3 className="text-sm font-bold text-slate-300 uppercase tracking-widest mb-4 border-b border-white/10 pb-2 flex items-center gap-2">
            <UploadCloud className="w-4 h-4" /> Upload Evidence Artifact
          </h3>
          
          <div 
            className={cn(
              "flex-1 border-2 border-dashed rounded-sm flex flex-col items-center justify-center p-8 transition-colors cursor-pointer",
              isDragging ? "border-rose-500 bg-rose-500/10" : "border-slate-700 bg-slate-900/50 hover:bg-slate-800/50"
            )}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input 
              type="file" 
              className="hidden" 
              ref={fileInputRef} 
              accept="image/*"
              onChange={(e) => e.target.files && handleFileSelect(e.target.files[0])}
            />
            
            {preview ? (
              <div className="flex flex-col items-center">
                <img src={preview} alt="Evidence Preview" className="max-h-[250px] object-contain mb-4 border border-white/10 rounded-sm shadow-2xl" />
                <p className="text-xs text-slate-400 font-mono">{file?.name}</p>
              </div>
            ) : (
               <div className="flex flex-col items-center text-slate-500">
                 <UploadCloud className="w-16 h-16 mb-4 opacity-50" />
                 <p className="font-bold uppercase tracking-widest mb-1">Drag & Drop Leaked Screenshot</p>
                 <p className="text-xs">Supports PNG, JPEG. Must contain forensic DCT signature.</p>
               </div>
            )}
          </div>
          
          <div className="mt-6 flex justify-end">
            <button 
              disabled={!file || status === 'analyzing'}
              onClick={runForensics}
              className="px-6 py-3 bg-rose-600 hover:bg-rose-700 text-white font-bold uppercase tracking-widest text-sm rounded-sm disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(225,29,72,0.3)] hover:shadow-[0_0_25px_rgba(225,29,72,0.5)]"
            >
              {status === 'analyzing' ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Deep Scanning DCT Grid...</>
               ) : (
                <><Fingerprint className="w-4 h-4" /> Run Forensics Extract</>
               )}
            </button>
          </div>
        </div>

        {/* Results Pane */}
        <div className="glass-panel p-6 border border-white/5 rounded-sm flex flex-col relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 pointer-events-none">
            <ShieldCheck className="w-64 h-64 text-slate-500" />
          </div>

          <h3 className="text-sm font-bold text-slate-300 uppercase tracking-widest mb-4 border-b border-white/10 pb-2 flex items-center gap-2">
            Extraction Protocol Result
          </h3>

          <div className="flex-1 flex flex-col justify-center relative z-10">
             {status === 'idle' && (
                <div className="text-center text-slate-500 font-mono text-sm">
                  STANDBY... <br/> Awaiting visual artifact input.
                </div>
             )}

             {status === 'analyzing' && (
                <div className="space-y-4">
                  <div className="h-2 w-full bg-slate-800 rounded overflow-hidden">
                    <div className="h-full bg-rose-500 animate-[pulse_1s_infinite_ease-in-out]" style={{width: '60%'}}></div>
                  </div>
                  <p className="text-xs font-mono text-rose-400">Isolating frequency variants...</p>
                  <p className="text-[10px] font-mono text-slate-500">Executing inverse Discrete Cosine Transform (DCT) on macroblocks.</p>
                </div>
             )}

             {status === 'success' && result && (
               <div className="animate-in fade-in zoom-in duration-500 space-y-4">
                 
                 {isAnalogRecovery && (
                   <div className="bg-yellow-950/40 border border-yellow-500/50 p-4 rounded-sm flex items-start gap-3 animate-pulse">
                      <AlertTriangle className="w-5 h-5 text-yellow-500 mt-0.5 shrink-0" />
                      <div>
                        <h4 className="text-yellow-500 font-bold uppercase text-xs tracking-widest mb-1">Severe Lens Warping Detected</h4>
                        <p className="text-[10px] text-yellow-400/80 font-mono">Analog hole transmission (smartphone photo) detected. Linear DCT matrices corrupted. Deep Spatial SIFT Re-alignment executed to recover origin signature.</p>
                      </div>
                   </div>
                 )}

                 <div className="bg-red-950/40 border-2 border-red-500 p-6 rounded-sm shadow-[0_0_40px_rgba(239,68,68,0.2)] text-center relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-red-500 shadow-[0_0_10px_red]"></div>
                    <AlertTriangle className="w-16 h-16 text-red-500 mx-auto mb-4 animate-[pulse_2s_infinite]" />
                    <h4 className="text-red-500 font-bold uppercase tracking-[0.3em] text-xs mb-2">Forensic Identity Match Confirmed</h4>
                    <div className="bg-black/50 p-4 rounded border border-red-500/30 break-all">
                       <code className="text-2xl md:text-3xl font-mono text-white tracking-widest font-extrabold">{result}</code>
                    </div>
                    <p className="mt-6 text-[11px] text-red-400/80 uppercase tracking-widest font-bold">
                      Source Leak Identified. Endpoint lockdown recommended.
                    </p>
                 </div>
               </div>
             )}

             {status === 'error' && (
               <div className="text-center p-6 border border-yellow-500/30 bg-yellow-950/20 rounded-sm">
                 <AlertTriangle className="w-10 h-10 text-yellow-500 mx-auto mb-3" />
                 <h4 className="text-yellow-500 font-bold uppercase tracking-widest text-sm mb-2">Extraction Failure</h4>
                 <p className="text-xs text-yellow-400/80 font-mono">{result}</p>
               </div>
             )}
          </div>
        </div>

      </div>
    </div>
  );
}
