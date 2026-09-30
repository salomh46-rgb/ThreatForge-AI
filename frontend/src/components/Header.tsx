import React from 'react';
import {
  ShieldCheck,
  Download,
  Code2,
  Flame,
  RefreshCw,
  GitPullRequest,
  Award,
  Sliders,
  ShieldAlert
} from 'lucide-react';
import type { ArchitectureTopology } from '../types';

interface HeaderProps {
  topology: ArchitectureTopology | null;
  onOpenInput: () => void;
  onExport: () => void;
  onSimulateAll: () => void;
  isSimulating: boolean;
  onResetAttack: () => void;
  onOpenCIGate: () => void;
  onOpenCompliance: () => void;
  onOpenPolicies: () => void;
  onOpenRiskAccept: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  topology,
  onOpenInput,
  onExport,
  onSimulateAll,
  isSimulating,
  onResetAttack,
  onOpenCIGate,
  onOpenCompliance,
  onOpenPolicies,
  onOpenRiskAccept
}) => {
  const score = topology?.security_score ?? 100;
  const grade = topology?.summary.security_grade ?? 'A';

  const getScoreColor = () => {
    if (score >= 90) return 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10';
    if (score >= 75) return 'text-sky-400 border-sky-500/40 bg-sky-500/10';
    if (score >= 50) return 'text-amber-400 border-amber-500/40 bg-amber-500/10';
    return 'text-red-400 border-red-500/40 bg-red-500/10';
  };

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md px-5 flex items-center justify-between z-20">
      {/* Brand & Logo */}
      <div className="flex items-center gap-3">
        <div className="relative p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-indigo-500/20 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]">
          <ShieldCheck className="w-5 h-5" />
          <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyan-400 rounded-full animate-ping" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-bold text-slate-100 tracking-tight m-0">ThreatForge AI</h1>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-indigo-950 border border-indigo-700 text-indigo-300 font-bold">
              Enterprise v2.0
            </span>
          </div>
          <p className="text-[11px] text-slate-400 m-0">Cloud Threat Modeling & CI/CD Security</p>
        </div>
      </div>

      {/* Enterprise Feature Navigation */}
      <div className="hidden lg:flex items-center gap-1.5 bg-slate-900/90 p-1 rounded-xl border border-slate-800 text-xs">
        <button
          onClick={onOpenCIGate}
          className="px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-cyan-300 hover:bg-slate-800 flex items-center gap-1.5 transition-all"
        >
          <GitPullRequest className="w-3.5 h-3.5 text-cyan-400" />
          CI/CD Gate
        </button>

        <button
          onClick={onOpenCompliance}
          className="px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-emerald-300 hover:bg-slate-800 flex items-center gap-1.5 transition-all"
        >
          <Award className="w-3.5 h-3.5 text-emerald-400" />
          Compliance Matrix
        </button>

        <button
          onClick={onOpenRiskAccept}
          className="px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-amber-300 hover:bg-slate-800 flex items-center gap-1.5 transition-all"
        >
          <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
          Risk Registry
        </button>

        <button
          onClick={onOpenPolicies}
          className="px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-purple-300 hover:bg-slate-800 flex items-center gap-1.5 transition-all"
        >
          <Sliders className="w-3.5 h-3.5 text-purple-400" />
          OPA Policies
        </button>
      </div>

      {/* Stats & Actions */}
      <div className="flex items-center gap-2.5">
        {topology && (
          <div className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border font-mono text-xs ${getScoreColor()}`}>
            <span>Score:</span>
            <strong className="font-bold">{score}/100</strong>
            <span className="px-1 rounded text-[10px] font-black bg-slate-900 border border-current">
              {grade}
            </span>
          </div>
        )}

        {/* Attack Simulator */}
        {topology && topology.attack_paths.length > 0 && (
          <button
            onClick={isSimulating ? onResetAttack : onSimulateAll}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border flex items-center gap-1.5 transition-all ${
              isSimulating
                ? 'bg-red-500/20 text-red-300 border-red-500/50 shadow-[0_0_12px_rgba(239,68,68,0.4)]'
                : 'bg-slate-900 text-slate-200 border-slate-700 hover:border-red-500/50 hover:text-red-300'
            }`}
          >
            {isSimulating ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-red-400" />
                Reset
              </>
            ) : (
              <>
                <Flame className="w-3.5 h-3.5 text-red-400" />
                Simulate ({topology.attack_paths.length})
              </>
            )}
          </button>
        )}

        {/* Input / Change Architecture */}
        <button
          onClick={onOpenInput}
          className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 hover:border-cyan-500/50 flex items-center gap-1.5 transition-all"
        >
          <Code2 className="w-3.5 h-3.5 text-cyan-400" />
          IaC Code
        </button>

        {/* Export CISO Report */}
        {topology && (
          <button
            onClick={onExport}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 shadow-[0_0_12px_rgba(6,182,212,0.3)] transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            Export Audit
          </button>
        )}
      </div>
    </header>
  );
};
