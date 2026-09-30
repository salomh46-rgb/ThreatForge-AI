import React from 'react';
import { ShieldCheck, Download, Code2, Flame, RefreshCw } from 'lucide-react';
import type { ArchitectureTopology } from '../types';

interface HeaderProps {
  topology: ArchitectureTopology | null;
  onOpenInput: () => void;
  onExport: () => void;
  onSimulateAll: () => void;
  isSimulating: boolean;
  onResetAttack: () => void;
  loading?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  topology,
  onOpenInput,
  onExport,
  onSimulateAll,
  isSimulating,
  onResetAttack
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
    <header className="h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md px-6 flex items-center justify-between z-20">
      {/* Brand & Logo */}
      <div className="flex items-center gap-3">
        <div className="relative p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-indigo-500/20 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]">
          <ShieldCheck className="w-6 h-6" />
          <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyan-400 rounded-full animate-ping" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold text-slate-100 tracking-tight m-0">ThreatForge AI</h1>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-700/50 text-cyan-300">
              STRIDE & MITRE Engine
            </span>
          </div>
          <p className="text-xs text-slate-400 m-0">Zero-Trust Cloud Architecture Security</p>
        </div>
      </div>

      {/* Center Stats (Score & Threats) */}
      {topology && (
        <div className="hidden md:flex items-center gap-4">
          {/* Security Score Badge */}
          <div className={`flex items-center gap-2 px-3 py-1 rounded-lg border font-mono text-xs ${getScoreColor()}`}>
            <span>Score:</span>
            <strong className="text-sm font-bold">{score}/100</strong>
            <span className="px-1.5 py-0.2 rounded font-black text-[11px] bg-slate-900 border border-current">
              Grade {grade}
            </span>
          </div>

          {/* Quick Threat Counts */}
          <div className="flex items-center gap-2 text-xs font-mono">
            {topology.summary.critical_threats > 0 && (
              <span className="px-2 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/30 font-semibold">
                {topology.summary.critical_threats} Critical
              </span>
            )}
            {topology.summary.high_threats > 0 && (
              <span className="px-2 py-1 rounded bg-orange-500/10 text-orange-400 border border-orange-500/30 font-semibold">
                {topology.summary.high_threats} High
              </span>
            )}
            <span className="text-slate-400">
              {topology.nodes.length} nodes · {topology.edges.length} flows
            </span>
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex items-center gap-3">
        {/* Red Team Attack Simulation Button */}
        {topology && topology.attack_paths.length > 0 && (
          <button
            onClick={isSimulating ? onResetAttack : onSimulateAll}
            className={`px-3 py-2 rounded-lg text-xs font-medium border flex items-center gap-2 transition-all ${
              isSimulating
                ? 'bg-red-500/20 text-red-300 border-red-500/50 shadow-[0_0_12px_rgba(239,68,68,0.4)]'
                : 'bg-slate-900 text-slate-200 border-slate-700 hover:border-red-500/50 hover:text-red-300'
            }`}
          >
            {isSimulating ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-red-400" />
                Reset Attack
              </>
            ) : (
              <>
                <Flame className="w-3.5 h-3.5 text-red-400" />
                Simulate Attack ({topology.attack_paths.length})
              </>
            )}
          </button>
        )}

        {/* Input / Change Architecture */}
        <button
          onClick={onOpenInput}
          className="px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 hover:border-cyan-500/50 flex items-center gap-2 transition-all"
        >
          <Code2 className="w-3.5 h-3.5 text-cyan-400" />
          Load / Edit Code
        </button>

        {/* Export CISO Report */}
        {topology && (
          <button
            onClick={onExport}
            className="px-3.5 py-2 rounded-lg text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-2 shadow-[0_0_12px_rgba(6,182,212,0.3)] transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            Export Audit Report
          </button>
        )}
      </div>
    </header>
  );
};
