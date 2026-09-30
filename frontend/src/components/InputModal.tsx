import React, { useState } from 'react';
import { X, Play, Code2, Sparkles, FileText } from 'lucide-react';
import type { PresetSummary } from '../types';

interface InputModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAnalyze: (code: string, format: string) => void;
  presets: PresetSummary[];
  onSelectPreset: (presetId: string) => void;
  currentCode: string;
  loading: boolean;
}

export const InputModal: React.FC<InputModalProps> = ({
  isOpen,
  onClose,
  onAnalyze,
  presets,
  onSelectPreset,
  currentCode,
  loading
}) => {
  const [code, setCode] = useState(currentCode);
  const [format, setFormat] = useState('auto');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!code.trim()) return;
    onAnalyze(code, format);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4">
      <div className="w-full max-w-4xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh] animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400">
              <Code2 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 m-0">
                Load Cloud Architecture / IaC Specification
              </h3>
              <p className="text-xs text-slate-400 m-0">
                Supports Terraform HCL (.tf), Docker Compose (.yml), and Mermaid Flowcharts
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

        {/* Preset Selector Banner */}
        <div className="px-6 py-3 bg-slate-950/40 border-b border-slate-800/80 flex items-center gap-3 overflow-x-auto text-xs">
          <span className="text-slate-400 font-mono font-medium flex items-center gap-1.5 flex-shrink-0">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            Sample Architectures:
          </span>
          <div className="flex items-center gap-2">
            {presets.map((p) => (
              <button
                key={p.id}
                onClick={() => {
                  onSelectPreset(p.id);
                }}
                className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 hover:border-cyan-500/50 flex-shrink-0 transition-all font-mono text-[11px]"
              >
                {p.title.split('—')[1]?.trim() || p.title}
              </button>
            ))}
          </div>
        </div>

        {/* Editor Form */}
        <form onSubmit={handleSubmit} className="p-6 flex-1 flex flex-col space-y-4 overflow-hidden">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Source Code (IaC / Diagram)
            </label>

            {/* Format selector */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
              {['auto', 'compose', 'terraform', 'mermaid'].map((f) => (
                <button
                  type="button"
                  key={f}
                  onClick={() => setFormat(f)}
                  className={`px-2 py-0.5 rounded capitalize transition-all ${
                    format === f
                      ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste your docker-compose.yml, main.tf, or Mermaid diagram here..."
            className="w-full flex-1 min-h-[340px] p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 resize-none shadow-inner leading-relaxed"
            spellCheck={false}
          />

          {/* Footer Controls */}
          <div className="flex items-center justify-between pt-2">
            <div className="text-[11px] text-slate-500 font-mono">
              {code.split('\n').length} lines · {code.length} characters
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading || !code.trim()}
                className="px-5 py-2.5 rounded-lg text-xs font-bold bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-white flex items-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all"
              >
                {loading ? (
                  <>Analyzing Architecture...</>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    Analyze & Map Threats
                  </>
                )}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
