import React, { useEffect, useState } from 'react';
import { AssetNode } from '../types';
import { AttackSurfaceGraph } from '../components/AttackSurfaceGraph';
import { Layers, Globe, RefreshCw } from 'lucide-react';

interface AttackSurfaceViewProps {
  attackSurface: AssetNode;
}

export const AttackSurfaceView: React.FC<AttackSurfaceViewProps> = ({ attackSurface }) => {
  const [graphData, setGraphData] = useState<AssetNode>(attackSurface);
  const [loading, setLoading] = useState<boolean>(false);

  const fetchLiveGraph = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/attack-surface', {
        headers: {
          Authorization: 'Bearer mock-token:user-ayush-001:RESEARCHER:Ayush Singh',
        },
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
          // Wrap or use first root node
          const root = data[0];
          setGraphData({
            id: root.id,
            name: root.name,
            domain: root.domain,
            type: root.type,
            status: root.assetStatus || 'AUTHORIZED',
            endpointsCount: root.endpointsCount || 0,
            techStack: root.techStack || ['HTTP/HTTPS'],
            children: root.children || [],
            priorityLabel: root.priorityLabel,
            priorityReason: root.priorityReason,
            assetStatus: root.assetStatus,
            scopeStatus: root.scopeStatus,
            policyDecision: root.policyDecision,
            programId: root.programId,
            scopeId: root.scopeId,
            discoverySessionId: root.discoverySessionId,
            researcherOwnership: root.researcherOwnership,
          });
        }
      }
    } catch {
      // Fallback silently to prop data
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLiveGraph();
  }, []);

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-red-400 uppercase tracking-wider mb-1">
            <Layers className="w-4 h-4" />
            <span>Target Reconnaissance Topology</span>
          </div>
          <h1 className="text-2xl font-black font-outfit uppercase tracking-wider text-slate-100">
            Attack Surface Map
          </h1>
          <p className="text-xs text-slate-400 font-sans">
            Interactive topology tree mapping subdomains, microservices, and endpoint signatures.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchLiveGraph}
            disabled={loading}
            className="p-1.5 rounded-lg bg-slate-900 border border-white/10 text-slate-400 hover:text-slate-200 transition-colors"
            title="Refresh Graph Intelligence"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-red-400' : ''}`} />
          </button>
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-slate-900 border border-white/10 text-slate-300 text-xs font-mono">
            <Globe className="w-4 h-4 text-red-400" />
            <span>Active Scope: {graphData.domain}</span>
          </div>
        </div>
      </div>

      <AttackSurfaceGraph rootNode={graphData} />
    </div>
  );
};
