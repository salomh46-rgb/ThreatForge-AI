import { useState, useEffect } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  BackgroundVariant,
  useReactFlow,
  ReactFlowProvider
} from '@xyflow/react';
import type { Node, Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { Header } from './components/Header';
import { CyberNode } from './components/CyberNode';
import { ThreatPanel } from './components/ThreatPanel';
import { InputModal } from './components/InputModal';
import { PatchModal } from './components/PatchModal';
import { CIGateModal } from './components/CIGateModal';
import { ComplianceModal } from './components/ComplianceModal';
import { RiskAcceptModal } from './components/RiskAcceptModal';
import { PolicyModal } from './components/PolicyModal';
import { FirewallModal } from './components/FirewallModal';
import type {
  ArchitectureTopology,
  ThreatFinding,
  AttackPath,
  PresetSummary,
  NodeModel,
  EdgeModel
} from './types';

const nodeTypes = {
  cyberNode: CyberNode
};

const DEFAULT_COMPOSE = `version: '3.8'

services:
  ingress_proxy:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - backend_api

  backend_api:
    image: mycompany/api:v1.2
    environment:
      - DB_HOST=postgres_db
      - DB_PASSWORD=super_insecure_hardcoded_pwd_2026
      - REDIS_HOST=cache_redis
    depends_on:
      - postgres_db
      - cache_redis

  postgres_db:
    image: postgres:15
    ports:
      - "5432:5432" # CRITICAL: Directly exposed to internet!
    environment:
      - POSTGRES_PASSWORD=super_insecure_hardcoded_pwd_2026
      - POSTGRES_DB=production_users

  cache_redis:
    image: redis:7-alpine
    ports:
      - "6379:6379" # CRITICAL: Redis exposed without requirepass or TLS!
`;

function layoutNodes(nodes: NodeModel[]): Node[] {
  const zoneY: Record<string, number> = {
    'Public Internet': 50,
    'DMZ / Ingress': 220,
    'Private App VPC': 400,
    'Secure Data Tier': 580,
    'Internal Management': 750
  };

  const zoneCount: Record<string, number> = {};

  return nodes.map((n) => {
    const y = zoneY[n.trust_zone] || 400;
    const countInZone = zoneCount[n.trust_zone] || 0;
    zoneCount[n.trust_zone] = countInZone + 1;
    const x = 120 + countInZone * 270;

    return {
      id: n.id,
      type: 'cyberNode',
      position: { x, y },
      data: n as any
    };
  });
}

function layoutEdges(edges: EdgeModel[], activePath: AttackPath | null): Edge[] {
  return edges.map((e) => {
    const isPathEdge =
      activePath &&
      activePath.path_nodes.includes(e.source) &&
      activePath.path_nodes.includes(e.target);

    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label || '',
      animated: isPathEdge || !e.is_encrypted,
      className: isPathEdge ? 'attack-path-active' : '',
      style: {
        stroke: isPathEdge ? '#ef4444' : e.is_encrypted ? '#38bdf8' : '#f59e0b',
        strokeWidth: isPathEdge ? 3.5 : 2
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: isPathEdge ? '#ef4444' : e.is_encrypted ? '#38bdf8' : '#f59e0b'
      },
      labelStyle: {
        fill: '#94a3b8',
        fontFamily: 'monospace',
        fontSize: 10,
        fontWeight: 500
      },
      labelBgStyle: {
        fill: '#090d16',
        fillOpacity: 0.85
      },
      labelBgPadding: [4, 2] as [number, number],
      labelBgBorderRadius: 4
    };
  });
}

function MainFlow() {
  const [topology, setTopology] = useState<ArchitectureTopology | null>(null);
  const [presets, setPresets] = useState<PresetSummary[]>([]);
  const [currentCode, setCurrentCode] = useState<string>(DEFAULT_COMPOSE);
  const [loading, setLoading] = useState(false);

  // Modals state
  const [isInputOpen, setIsInputOpen] = useState(false);
  const [isCIGateOpen, setIsCIGateOpen] = useState(false);
  const [isComplianceOpen, setIsComplianceOpen] = useState(false);
  const [isRiskModalOpen, setIsRiskModalOpen] = useState(false);
  const [isPolicyModalOpen, setIsPolicyModalOpen] = useState(false);
  const [isFirewallOpen, setIsFirewallOpen] = useState(false);

  const [selectedThreat, setSelectedThreat] = useState<ThreatFinding | null>(null);
  const [threatForRisk, setThreatForRisk] = useState<ThreatFinding | null>(null);
  const [activePath, setActivePath] = useState<AttackPath | null>(null);
  const [isSimulatingAll, setIsSimulatingAll] = useState(false);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const reactFlow = useReactFlow();

  const runAnalysis = async (code: string, format = 'auto') => {
    setLoading(true);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_code: code, format })
      });

      if (!res.ok) {
        const errorData = await res.json();
        alert(`Analysis Error: ${errorData.detail || 'Unknown error'}`);
        return;
      }

      const data: ArchitectureTopology = await res.json();
      setTopology(data);
      setCurrentCode(code);
      setIsInputOpen(false);
      setActivePath(null);
      setIsSimulatingAll(false);

      const flowNodes = layoutNodes(data.nodes);
      const flowEdges = layoutEdges(data.edges, null);

      setNodes(flowNodes);
      setEdges(flowEdges);

      setTimeout(() => {
        reactFlow.fitView({ padding: 0.2, duration: 600 });
      }, 100);
    } catch (err: any) {
      alert(`Network or Server error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetch('/api/presets')
      .then((res) => res.json())
      .then((data) => setPresets(data))
      .catch((err) => console.error('Failed to load presets:', err));

    runAnalysis(DEFAULT_COMPOSE, 'compose');
  }, []);

  const handleSelectPreset = async (presetId: string) => {
    try {
      const res = await fetch(`/api/presets/${presetId}`);
      const data = await res.json();
      if (data.code) {
        setCurrentCode(data.code);
        runAnalysis(data.code, data.format);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleSimulatePath = (path: AttackPath) => {
    if (activePath?.id === path.id) {
      setActivePath(null);
      if (topology) setEdges(layoutEdges(topology.edges, null));
      return;
    }

    setActivePath(path);
    if (topology) {
      setEdges(layoutEdges(topology.edges, path));
    }
  };

  const handleSimulateAll = () => {
    if (!topology || topology.attack_paths.length === 0) return;
    setIsSimulatingAll(true);
    handleSimulatePath(topology.attack_paths[0]);
  };

  const handleResetAttack = () => {
    setIsSimulatingAll(false);
    setActivePath(null);
    if (topology) setEdges(layoutEdges(topology.edges, null));
  };

  const handleFocusNode = (nodeId: string) => {
    const node = nodes.find((n) => n.id === nodeId);
    if (node) {
      reactFlow.setCenter(node.position.x + 100, node.position.y + 50, { zoom: 1.2, duration: 600 });
    }
  };

  const handleAcceptRiskClick = (threat: ThreatFinding) => {
    setThreatForRisk(threat);
    setIsRiskModalOpen(true);
  };

  const handleExport = async () => {
    if (!topology) return;
    try {
      const res = await fetch('/api/export/markdown', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(topology)
      });
      const markdown = await res.text();

      const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `ThreatForge_Enterprise_Report_${Date.now()}.md`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  return (
    <div className="w-full h-full flex flex-col bg-slate-950 text-slate-100 overflow-hidden font-sans">
      <Header
        topology={topology}
        onOpenInput={() => setIsInputOpen(true)}
        onExport={handleExport}
        onSimulateAll={handleSimulateAll}
        isSimulating={isSimulatingAll || !!activePath}
        onResetAttack={handleResetAttack}
        onOpenCIGate={() => setIsCIGateOpen(true)}
        onOpenCompliance={() => setIsComplianceOpen(true)}
        onOpenPolicies={() => setIsPolicyModalOpen(true)}
        onOpenFirewall={() => setIsFirewallOpen(true)}
        onOpenRiskAccept={() => {
          setThreatForRisk(topology?.threats[0] || null);
          setIsRiskModalOpen(true);
        }}
      />

      <div className="flex-1 flex relative overflow-hidden">
        {/* Canvas */}
        <div className="flex-1 h-full relative tactical-grid">
          {/* Trust Zone Floating Labels */}
          <div className="absolute left-6 top-4 z-10 flex flex-col gap-28 pointer-events-none opacity-40 font-mono text-[11px] uppercase tracking-widest text-slate-400">
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-sky-400" />
              Zone: Public Ingress
            </span>
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              Zone: DMZ & Gateways
            </span>
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-indigo-400" />
              Zone: Private Application VPC
            </span>
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              Zone: Crown Jewels & Data Tier
            </span>
          </div>

          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.2}
            maxZoom={2}
          >
            <Background color="#1e293b" gap={24} size={1.5} variant={BackgroundVariant.Dots} />
            <Controls className="!bg-slate-900 !border-slate-800 !text-slate-300 [&>button]:!border-slate-800 [&>button]:!fill-slate-300" />
            <MiniMap
              className="!bg-slate-950/80 !border-slate-800 !rounded-xl overflow-hidden"
              nodeColor={(n: any) => {
                const nodeData = n.data as NodeModel;
                if (nodeData?.highest_severity === 'CRITICAL') return '#ef4444';
                if (nodeData?.highest_severity === 'HIGH') return '#f97316';
                if (nodeData?.highest_severity === 'MEDIUM') return '#f59e0b';
                return '#38bdf8';
              }}
              maskColor="rgba(7, 9, 14, 0.7)"
            />
          </ReactFlow>
        </div>

        {/* Threat Panel */}
        {topology && (
          <ThreatPanel
            topology={topology}
            onSelectThreat={(t) => setSelectedThreat(t)}
            onSimulatePath={handleSimulatePath}
            activePathId={activePath?.id || null}
            onFocusNode={handleFocusNode}
            onAcceptRisk={handleAcceptRiskClick}
          />
        )}
      </div>

      {/* Modals */}
      <InputModal
        isOpen={isInputOpen}
        onClose={() => setIsInputOpen(false)}
        onAnalyze={(code, format) => runAnalysis(code, format)}
        presets={presets}
        onSelectPreset={handleSelectPreset}
        currentCode={currentCode}
        loading={loading}
      />

      <PatchModal threat={selectedThreat} onClose={() => setSelectedThreat(null)} />

      <CIGateModal
        isOpen={isCIGateOpen}
        onClose={() => setIsCIGateOpen(false)}
        currentCode={currentCode}
      />

      <ComplianceModal
        isOpen={isComplianceOpen}
        onClose={() => setIsComplianceOpen(false)}
        currentCode={currentCode}
      />

      <RiskAcceptModal
        isOpen={isRiskModalOpen}
        onClose={() => setIsRiskModalOpen(false)}
        threat={threatForRisk}
      />

      <PolicyModal
        isOpen={isPolicyModalOpen}
        onClose={() => setIsPolicyModalOpen(false)}
      />

      <FirewallModal
        isOpen={isFirewallOpen}
        onClose={() => setIsFirewallOpen(false)}
      />
    </div>
  );
}

export default function App() {
  return (
    <ReactFlowProvider>
      <MainFlow />
    </ReactFlowProvider>
  );
}
