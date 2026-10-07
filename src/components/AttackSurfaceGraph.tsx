import React, { useState } from 'react';
import { AssetNode, ResearchPriorityLabel } from '../types';
import { Layers, Globe, Server, Shield, Lock, ChevronRight, Terminal, Activity, FileText, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

interface AttackSurfaceGraphProps {
  rootNode: AssetNode;
}

export const AttackSurfaceGraph: React.FC<AttackSurfaceGraphProps> = ({ rootNode }) => {
  const [selectedNode, setSelectedNode] = useState<AssetNode>(rootNode.children?.[1] || rootNode);
  const [selectedCapability, setSelectedCapability] = useState<string>('RECONNAISSANCE');
  const [evalResult, setEvalResult] = useState<any | null>(null);
  const [evalLoading, setEvalLoading] = useState<boolean>(false);

  const getTypeBadge = (type: AssetNode['type']) => {
    switch (type) {
      case 'root':
      case 'DOMAIN':
        return 'bg-red-950/80 text-red-400 border-red-700/50';
      case 'api':
      case 'API_ENDPOINT':
        return 'bg-amber-950/80 text-amber-400 border-amber-700/50';
      case 'auth':
        return 'bg-purple-950/80 text-purple-400 border-purple-700/50';
      case 'admin':
        return 'bg-rose-950/80 text-rose-400 border-rose-700/50';
      case 'static':
      case 'URL':
        return 'bg-slate-900 text-slate-400 border-slate-700/50';
      default:
        return 'bg-blue-950/80 text-blue-400 border-blue-700/50';
    }
  };

  const getPriorityBadge = (priority?: ResearchPriorityLabel) => {
    switch (priority) {
      case 'HIGH PRIORITY':
        return 'bg-amber-950/90 text-amber-300 border-amber-600/60 shadow-[0_0_10px_rgba(245,158,11,0.2)]';
      case 'MEDIUM PRIORITY':
        return 'bg-blue-950/90 text-blue-300 border-blue-600/60';
      case 'LOW PRIORITY':
      default:
        return 'bg-slate-900 text-slate-400 border-slate-700/60';
    }
  };

  const handleEvaluateCapability = async () => {
    setEvalLoading(true);
    setEvalResult(null);
    try {
      const res = await fetch('/api/v1/attack-surface/evaluate-capability', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer mock-token:user-ayush-001:RESEARCHER:Ayush Singh',
        },
        body: JSON.stringify({
          programId: selectedNode.programId || 'prog-acme-01',
          target: selectedNode.domain,
          capability: selectedCapability,
        }),
      });
      const data = await res.json();
      setEvalResult(data);
    } catch (err: any) {
      setEvalResult({ error: err.message });
    } finally {
      setEvalLoading(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Left 2 Cols: Visual Hierarchy Map */}
      <div className="lg:col-span-2 glass-panel rounded-2xl p-6 border border-white/10 relative overflow-hidden bg-gradient-to-br from-[#0c0e17] via-[#090b12] to-[#0f111d]">
        <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-6">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-red-950/80 border border-red-700/50 flex items-center justify-center text-red-400">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold font-outfit uppercase tracking-wider text-slate-100">
                Attack Surface Mapping
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Interactive target topology map for {rootNode.domain}
              </p>
            </div>
          </div>

          <span className="text-xs font-mono px-2.5 py-1 rounded-md bg-slate-900 border border-white/10 text-slate-300">
            {rootNode.children?.length || 0} Subdomains / Assets Discovered
          </span>
        </div>

        {/* Root Node Display */}
        <div className="space-y-6">
          <div
            onClick={() => {
              setSelectedNode(rootNode);
              setEvalResult(null);
            }}
            className={`p-4 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
              selectedNode.id === rootNode.id
                ? 'bg-gradient-to-r from-red-950/80 to-slate-900 border-red-500/60 shadow-[0_0_20px_rgba(220,38,38,0.2)]'
                : 'bg-slate-900/80 border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-950/90 border border-red-700/60 flex items-center justify-center text-red-400 font-bold">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono font-bold text-slate-100 text-sm">{rootNode.domain}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono border uppercase ${getTypeBadge(rootNode.type)}`}>
                    {rootNode.type}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getPriorityBadge(rootNode.priorityLabel || 'LOW PRIORITY')}`}>
                    {rootNode.priorityLabel || 'LOW PRIORITY'}
                  </span>
                </div>
                <span className="text-xs text-slate-400 font-mono">
                  Root domain • {rootNode.endpointsCount} endpoints
                </span>
              </div>
            </div>

            <ChevronRight className="w-5 h-5 text-slate-500" />
          </div>

          {/* Children Tree Nodes */}
          <div className="pl-6 border-l-2 border-red-900/40 space-y-3 relative">
            {rootNode.children?.map((child) => {
              const isSelected = selectedNode.id === child.id;
              const childPriority = child.priorityLabel || (child.type === 'api' ? 'HIGH PRIORITY' : 'MEDIUM PRIORITY');

              return (
                <div key={child.id} className="relative group">
                  {/* Branch line connector */}
                  <div className="absolute -left-6 top-1/2 -translate-y-1/2 w-6 h-0.5 bg-red-900/40 group-hover:bg-red-500/60 transition-colors" />

                  <div
                    onClick={() => {
                      setSelectedNode(child);
                      setEvalResult(null);
                    }}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
                      isSelected
                        ? 'bg-gradient-to-r from-red-950/70 to-slate-900 border-red-500/60 shadow-[0_0_15px_rgba(220,38,38,0.2)]'
                        : 'bg-slate-900/60 border-white/10 hover:border-white/20 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-8 h-8 rounded-lg bg-slate-950 border border-white/10 flex items-center justify-center text-slate-300 font-bold shrink-0">
                        <Server className="w-4 h-4 text-slate-400" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 truncate flex-wrap">
                          <span className="font-mono font-semibold text-slate-100 text-xs truncate">
                            {child.name.includes('.') ? child.name : `${child.name}.${rootNode.domain}`}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[9px] font-mono border uppercase shrink-0 ${getTypeBadge(child.type)}`}>
                            {child.type}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono flex items-center gap-3 mt-0.5">
                          <span>{child.endpointsCount} endpoints</span>
                          <span className="truncate">Stack: {child.techStack?.slice(0, 2).join(', ') || 'HTTP'}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getPriorityBadge(childPriority)}`}>
                        {childPriority}
                      </span>
                      <ChevronRight className={`w-4 h-4 transition-transform ${isSelected ? 'text-red-400 translate-x-1' : 'text-slate-600'}`} />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Right 1 Col: Selected Asset Drawer & Capability Preview Panel */}
      <div className="glass-panel rounded-2xl p-6 border border-white/10 flex flex-col justify-between space-y-6 bg-slate-950/90">
        <div>
          <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
            <span className="text-xs font-mono uppercase text-slate-400 font-semibold">Intelligence Detail View</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getPriorityBadge(selectedNode.priorityLabel || 'MEDIUM PRIORITY')}`}>
              {selectedNode.priorityLabel || 'MEDIUM PRIORITY'}
            </span>
          </div>

          <div className="mb-4">
            <h4 className="text-lg font-bold font-mono text-slate-100 break-all">{selectedNode.domain}</h4>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">Asset ID: {selectedNode.id}</p>
            {selectedNode.priorityReason && (
              <p className="text-[11px] text-amber-300 font-mono mt-1 p-2 rounded bg-amber-950/30 border border-amber-800/30">
                Reason: {selectedNode.priorityReason}
              </p>
            )}
          </div>

          <div className="space-y-4 text-xs font-mono">
            {/* Status Breakdown */}
            <div className="p-3 rounded-xl bg-slate-900/80 border border-white/10 space-y-1.5 text-[11px]">
              <div className="flex justify-between">
                <span className="text-slate-400">Asset Status:</span>
                <span className="text-slate-200 font-bold">{selectedNode.assetStatus || selectedNode.status || 'AUTHORIZED'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Scope Status:</span>
                <span className="text-emerald-400 font-bold">{selectedNode.scopeStatus || 'IN_SCOPE'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Policy Decision:</span>
                <span className="text-blue-400 font-bold">{selectedNode.policyDecision || 'ALLOW'}</span>
              </div>
            </div>

            {/* Provenance Details */}
            <div className="p-3 rounded-xl bg-slate-900/80 border border-white/10 space-y-1 text-[10px] text-slate-400">
              <div className="text-slate-300 font-bold uppercase text-[9px] mb-1">Provenance Tracking</div>
              <div>Program ID: {selectedNode.programId || 'prog-acme-01'}</div>
              <div>Scope ID: {selectedNode.scopeId || 'scope-acme-root'}</div>
              <div>Session ID: {selectedNode.discoverySessionId || 'sess-system-init'}</div>
              <div>Ownership: {selectedNode.researcherOwnership || 'OWNED'}</div>
            </div>

            {/* Tech Stack */}
            <div>
              <span className="text-slate-400 block mb-1.5 uppercase text-[10px]">Contextual Tech Stack</span>
              <div className="flex flex-wrap gap-1.5">
                {selectedNode.techStack?.map((tech) => (
                  <span
                    key={tech}
                    className="px-2 py-0.5 rounded bg-slate-900 border border-white/10 text-slate-300 text-[10px]"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </div>

            {/* Research Capability Evaluation Preview */}
            <div className="pt-3 border-t border-white/10 space-y-2">
              <span className="text-slate-300 font-bold uppercase text-[10px] block">
                Research Capability Preview
              </span>
              <div className="flex items-center gap-2">
                <select
                  value={selectedCapability}
                  onChange={(e) => setSelectedCapability(e.target.value)}
                  className="bg-slate-900 border border-white/10 text-slate-200 text-[11px] rounded px-2 py-1.5 focus:outline-none focus:border-red-500 w-full"
                >
                  <option value="RECONNAISSANCE">RECONNAISSANCE</option>
                  <option value="ASSET_ENUMERATION">ASSET_ENUMERATION</option>
                  <option value="SUBDOMAIN_DISCOVERY">SUBDOMAIN_DISCOVERY</option>
                  <option value="EXPLOITATION">EXPLOITATION</option>
                </select>
                <button
                  onClick={handleEvaluateCapability}
                  disabled={evalLoading}
                  className="bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-700/50 text-[10px] font-bold px-3 py-1.5 rounded transition-all shrink-0"
                >
                  {evalLoading ? 'Evaluating...' : 'Evaluate'}
                </button>
              </div>

              {evalResult && (
                <div className="p-3 rounded-xl bg-slate-900 border border-white/15 space-y-1.5 text-[11px] animate-fade-in">
                  <div className="flex items-center justify-between">
                    <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider">[AUTHORIZATION PREVIEW ONLY]</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        evalResult.decision === 'ALLOW'
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-700/50'
                          : evalResult.decision === 'REVIEW_REQUIRED'
                          ? 'bg-amber-950 text-amber-300 border-amber-700/50'
                          : 'bg-rose-950 text-rose-300 border-rose-700/50'
                      }`}
                    >
                      {evalResult.decision || 'ERROR'}
                    </span>
                  </div>
                  <div className="text-slate-300 font-mono text-[10px]">
                    {evalResult.reason || evalResult.error}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="pt-4 border-t border-white/10">
          <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            <span>Read-Only Intelligence Graph Active</span>
          </div>
        </div>
      </div>
    </div>
  );
};
