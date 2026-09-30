import React, { useState } from 'react';
import { X, Check, Copy, Wrench } from 'lucide-react';
import type { ThreatFinding } from '../types';

interface PatchModalProps {
  threat: ThreatFinding | null;
  onClose: () => void;
}

export const PatchModal: React.FC<PatchModalProps> = ({ threat, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!threat) return null;

  const handleCopy = () => {
    if (threat.code_patch) {
      navigator.clipboard.writeText(threat.code_patch);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] animate-in fade-in zoom-in-95 duration-200">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-700/50 text-cyan-400">
              <Wrench className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 m-0">
                1-Click Automated Security Remediation
              </h3>
              <p className="text-xs text-slate-400 m-0">
                {threat.stride_category} · CVSS {threat.cvss_score} · {threat.mitre_technique}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-4">
          <div className="space-y-1">
            <h4 className="text-sm font-semibold text-slate-200">{threat.title}</h4>
            <p className="text-xs text-slate-400 leading-relaxed">{threat.description}</p>
          </div>

          <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-800/40 space-y-1 text-xs">
            <span className="font-semibold text-cyan-300">Architect Advice:</span>
            <p className="text-cyan-200/90 leading-relaxed">{threat.remediation_advice}</p>
          </div>

          {/* Patch Diff Box */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-mono text-slate-400">Suggested Code Diff / Hardening Configuration:</span>
              <button
                onClick={handleCopy}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-all text-xs font-mono"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-cyan-400" />
                    Copy Patch
                  </>
                )}
              </button>
            </div>

            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre leading-relaxed shadow-inner">
              <code>{threat.code_patch || '// No automated diff generated for this rule.'}</code>
            </pre>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-slate-800 bg-slate-950/60 flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close
          </button>
          <button
            onClick={handleCopy}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-2 shadow-[0_0_12px_rgba(6,182,212,0.3)] transition-all"
          >
            <Copy className="w-3.5 h-3.5" />
            Copy Hardening Patch
          </button>
        </div>
      </div>
    </div>
  );
};
