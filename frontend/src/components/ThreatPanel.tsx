import React, { useState } from 'react';
import {
  Flame,
  Shield,
  ChevronRight,
  Wrench,
  Crosshair
} from 'lucide-react';
import type { ArchitectureTopology, ThreatFinding, AttackPath, ThreatSeverity } from '../types';

interface ThreatPanelProps {
  topology: ArchitectureTopology;
  onSelectThreat: (threat: ThreatFinding) => void;
  onSimulatePath: (path: AttackPath) => void;
  activePathId: string | null;
  onFocusNode: (nodeId: string) => void;
}

export const ThreatPanel: React.FC<ThreatPanelProps> = ({
  topology,
  onSelectThreat,
  onSimulatePath,
  activePathId,
  onFocusNode
}) => {
  const [activeTab, setActiveTab] = useState<'threats' | 'paths'>('threats');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  const filteredThreats = topology.threats.filter((t) => {
    if (selectedSeverity !== 'ALL' && t.severity !== selectedSeverity) return false;
    return true;
  });

  const getSeverityBadge = (sev: ThreatSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'LOW':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
    }
  };

  return (
    <aside className="w-96 h-[calc(100vh-4rem)] border-l border-slate-800 bg-slate-950/95 flex flex-col z-10 backdrop-blur-md">
      {/* Tabs */}
      <div className="flex border-b border-slate-800 bg-slate-900/60 p-1.5 gap-1">
        <button
          onClick={() => setActiveTab('threats')}
          className={`flex-1 py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
            activeTab === 'threats'
              ? 'bg-slate-800 text-cyan-400 shadow-sm border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          STRIDE Threats ({topology.threats.length})
        </button>

        <button
          onClick={() => setActiveTab('paths')}
          className={`flex-1 py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
            activeTab === 'paths'
              ? 'bg-red-950/40 text-red-400 shadow-sm border border-red-800/50'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Flame className="w-3.5 h-3.5" />
          Attack Paths ({topology.attack_paths.length})
        </button>
      </div>

      {/* Main Tab Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {activeTab === 'threats' ? (
          <>
            {/* Filter Chips */}
            <div className="space-y-2">
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-[11px] font-mono">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
                  <button
                    key={s}
                    onClick={() => setSelectedSeverity(s)}
                    className={`px-2 py-0.5 rounded border transition-all ${
                      selectedSeverity === s
                        ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50'
                        : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            {/* Threat Cards */}
            <div className="space-y-3">
              {filteredThreats.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-xs">
                  No threats found matching selected filter.
                </div>
              ) : (
                filteredThreats.map((threat) => (
                  <div
                    key={threat.id}
                    className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/90 hover:border-slate-700 transition-all space-y-2.5 group"
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityBadge(
                              threat.severity
                            )}`}
                          >
                            {threat.severity}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-purple-950/60 text-purple-300 border border-purple-800/40">
                            {threat.stride_category}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400">
                            CVSS {threat.cvss_score}
                          </span>
                        </div>
                        <h4 className="text-xs font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors leading-tight">
                          {threat.title}
                        </h4>
                      </div>
                    </div>

                    {/* Target Node & MITRE */}
                    <div className="text-[11px] text-slate-400 flex items-center justify-between">
                      <button
                        onClick={() => onFocusNode(threat.target_id)}
                        className="inline-flex items-center gap-1 text-cyan-400 hover:underline truncate max-w-[180px]"
                        title={threat.target_name}
                      >
                        <Crosshair className="w-3 h-3 flex-shrink-0" />
                        <span className="truncate">{threat.target_name}</span>
                      </button>
                      <span className="text-[10px] font-mono text-slate-500 truncate max-w-[140px]">
                        {threat.mitre_technique.split('-')[0]}
                      </span>
                    </div>

                    {/* Description */}
                    <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-3">
                      {threat.description}
                    </p>

                    {/* Remediation Button */}
                    <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between">
                      <div className="text-[10px] text-slate-500 font-mono">
                        Blast: {threat.blast_radius_nodes.length} node(s)
                      </div>
                      <button
                        onClick={() => onSelectThreat(threat)}
                        className="px-2.5 py-1 rounded-md text-[11px] font-medium bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-700/50 flex items-center gap-1.5 transition-all"
                      >
                        <Wrench className="w-3 h-3 text-cyan-400" />
                        View Patch Diff
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </>
        ) : (
          /* Attack Paths Tab */
          <div className="space-y-3">
            <div className="p-3 rounded-xl bg-red-950/20 border border-red-900/40 text-[11px] text-red-300 space-y-1">
              <div className="font-semibold flex items-center gap-1.5 text-red-200">
                <Flame className="w-4 h-4 text-red-400" />
                Autonomous Red Team Pivots
              </div>
              <p className="text-red-300/80 leading-relaxed text-[11px]">
                These chains represent zero-barrier pathways through which external attackers can penetrate
                ingress and exfiltrate databases or secrets.
              </p>
            </div>

            {topology.attack_paths.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs">
                No penetrable multi-hop attack vectors detected!
              </div>
            ) : (
              topology.attack_paths.map((path) => {
                const isActive = activePathId === path.id;
                return (
                  <div
                    key={path.id}
                    className={`p-3.5 rounded-xl border transition-all space-y-2.5 ${
                      isActive
                        ? 'bg-red-950/40 border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]'
                        : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                        {path.risk_level}
                      </span>
                      <button
                        onClick={() => onSimulatePath(path)}
                        className={`px-2.5 py-1 rounded text-[11px] font-semibold flex items-center gap-1.5 transition-all ${
                          isActive
                            ? 'bg-red-500 text-white shadow-md'
                            : 'bg-slate-800 text-slate-200 hover:bg-red-500/20 hover:text-red-300 border border-slate-700'
                        }`}
                      >
                        <Flame className="w-3 h-3" />
                        {isActive ? 'Simulating...' : 'Simulate Pivot'}
                      </button>
                    </div>

                    <h4 className="text-xs font-bold text-slate-100">{path.name}</h4>

                    {/* Step-by-step nodes */}
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] text-slate-300 space-y-1">
                      <div className="text-slate-500 uppercase tracking-wider text-[9px]">Pivoting Path:</div>
                      <div className="flex items-center flex-wrap gap-1">
                        {path.path_nodes.map((nodeId, idx) => (
                          <React.Fragment key={nodeId}>
                            <button
                              onClick={() => onFocusNode(nodeId)}
                              className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 truncate max-w-[120px]"
                            >
                              {nodeId}
                            </button>
                            {idx < path.path_nodes.length - 1 && (
                              <ChevronRight className="w-3 h-3 text-red-500 flex-shrink-0" />
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed">{path.description}</p>
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>
    </aside>
  );
};
