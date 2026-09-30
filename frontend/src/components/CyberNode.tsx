import React, { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import {
  Database,
  HardDrive,
  Box,
  Globe,
  Network,
  Server,
  KeyRound,
  ShieldAlert,
  Layers,
  ArrowLeftRight,
  AlertTriangle,
  Lock,
  Unlock
} from 'lucide-react';
import type { NodeModel, ThreatSeverity } from '../types';

const getNodeIcon = (type: string) => {
  switch (type) {
    case 'internet':
      return <Globe className="w-5 h-5 text-sky-400" />;
    case 'load_balancer':
      return <ArrowLeftRight className="w-5 h-5 text-cyan-400" />;
    case 'api_gateway':
      return <Network className="w-5 h-5 text-indigo-400" />;
    case 'database':
      return <Database className="w-5 h-5 text-amber-400" />;
    case 'cache':
      return <HardDrive className="w-5 h-5 text-rose-400" />;
    case 'storage_bucket':
      return <Box className="w-5 h-5 text-teal-400" />;
    case 'auth_service':
      return <KeyRound className="w-5 h-5 text-emerald-400" />;
    case 'firewall':
      return <ShieldAlert className="w-5 h-5 text-purple-400" />;
    case 'microservice':
      return <Server className="w-5 h-5 text-blue-400" />;
    default:
      return <Layers className="w-5 h-5 text-slate-400" />;
  }
};

const getSeverityBorder = (sev?: ThreatSeverity | null) => {
  if (sev === 'CRITICAL') {
    return 'border-red-500 shadow-[0_0_16px_rgba(239,68,68,0.55)] bg-red-950/20';
  }
  if (sev === 'HIGH') {
    return 'border-orange-500 shadow-[0_0_14px_rgba(249,115,22,0.45)] bg-orange-950/20';
  }
  if (sev === 'MEDIUM') {
    return 'border-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.35)] bg-amber-950/20';
  }
  return 'border-slate-700/80 shadow-[0_0_8px_rgba(30,41,59,0.3)] bg-slate-900/60';
};

export const CyberNode: React.FC<NodeProps> = memo(({ data, selected }) => {
  const node = data as unknown as NodeModel;
  const isAttackTarget = node.highest_severity === 'CRITICAL';

  return (
    <div
      className={`relative min-w-[210px] max-w-[250px] rounded-xl border p-3.5 backdrop-blur-md transition-all duration-300 ${getSeverityBorder(
        node.highest_severity
      )} ${selected ? 'ring-2 ring-cyan-400 ring-offset-2 ring-offset-slate-950' : ''}`}
    >
      {/* React Flow Handles */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-3 !h-3 !bg-cyan-500 !border-2 !border-slate-950 !-top-1.5"
      />
      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-3 !h-3 !bg-cyan-500 !border-2 !border-slate-950 !-bottom-1.5"
      />

      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-slate-800/80 border border-slate-700/50">
            {getNodeIcon(node.type)}
          </div>
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">
            {node.type.replace('_', ' ')}
          </span>
        </div>

        {/* Public Access Badge */}
        {node.is_public ? (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-500/20 text-red-400 border border-red-500/30">
            <Unlock className="w-2.5 h-2.5" /> Public
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
            <Lock className="w-2.5 h-2.5" /> Private
          </span>
        )}
      </div>

      {/* Label */}
      <div className="font-semibold text-sm text-slate-100 truncate mb-1" title={node.label}>
        {node.label}
      </div>

      {/* Trust Zone */}
      <div className="text-[11px] text-slate-400 mb-2 truncate font-mono">
        <span className="text-slate-500">Zone:</span> {node.trust_zone}
      </div>

      {/* Footer Info: Ports & Threat Counter */}
      <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[11px]">
        <div className="flex items-center gap-1 text-slate-400 font-mono text-[10px]">
          {node.ports && node.ports.length > 0 ? (
            <span>:{node.ports.join(', :')}</span>
          ) : (
            <span className="text-slate-600">internal</span>
          )}
        </div>

        {/* Threats Counter Pill */}
        {node.threat_count > 0 && (
          <div
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold ${
              isAttackTarget
                ? 'bg-red-500 text-white animate-pulse'
                : node.highest_severity === 'HIGH'
                ? 'bg-orange-500 text-white'
                : 'bg-amber-500 text-black'
            }`}
          >
            <AlertTriangle className="w-2.5 h-2.5" />
            {node.threat_count} {node.threat_count === 1 ? 'threat' : 'threats'}
          </div>
        )}
      </div>
    </div>
  );
});

CyberNode.displayName = 'CyberNode';
