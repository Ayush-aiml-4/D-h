import crypto from 'crypto';
import { GraphNode, GraphEdge, RelationshipGraph } from './types.ts';

export function buildProvenanceGraph(input: {
  target: string;
  pageUrl: string;
  resourceUrls?: string[];
  endpoints?: string[];
  observationIds?: string[];
  evidenceIds?: string[];
  findingCandidateId?: string;
  reportId?: string;
}): RelationshipGraph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const addNode = (type: GraphNode['type'], label: string, metadata: Record<string, string> = {}) => {
    const id = `node-${type}-${crypto.randomBytes(3).toString('hex')}`;
    nodes.push({ id, type, label, metadata });
    return id;
  };

  const addEdge = (from: string, to: string, relation: string) => {
    edges.push({ id: `edge-${crypto.randomBytes(3).toString('hex')}`, from, to, relation });
  };

  const targetId = addNode('TARGET', input.target);
  const pageId = addNode('PAGE', input.pageUrl);
  addEdge(targetId, pageId, 'HAS_PAGE');

  for (const r of input.resourceUrls || []) {
    const rid = addNode('RESOURCE', r);
    addEdge(pageId, rid, 'LOADS_RESOURCE');
  }

  for (const ep of input.endpoints || []) {
    const eid = addNode('ENDPOINT', ep);
    addEdge(pageId, eid, 'REFERENCES_ENDPOINT');
  }

  for (const oid of input.observationIds || []) {
    const oidNode = addNode('OBSERVATION', oid);
    addEdge(pageId, oidNode, 'PRODUCED_OBSERVATION');
  }

  for (const evid of input.evidenceIds || []) {
    const evidNode = addNode('EVIDENCE', evid);
    addEdge(pageId, evidNode, 'HAS_EVIDENCE');
  }

  if (input.findingCandidateId) {
    const fid = addNode('FINDING_CANDIDATE', input.findingCandidateId);
    for (const n of nodes.filter((x) => x.type === 'OBSERVATION')) {
      addEdge(n.id, fid, 'SUPPORTS_CANDIDATE');
    }
  }

  if (input.reportId && input.findingCandidateId) {
    const rid = addNode('REPORT', input.reportId);
    const fnode = nodes.find((n) => n.label === input.findingCandidateId);
    if (fnode) addEdge(fnode.id, rid, 'DRAFTS_REPORT');
  }

  return { nodes, edges };
}

export function explainFindingPath(graph: RelationshipGraph, findingLabel: string): string[] {
  const finding = graph.nodes.find((n) => n.type === 'FINDING_CANDIDATE' && n.label === findingLabel);
  if (!finding) return ['No provenance path found'];
  const path: string[] = [`Finding candidate: ${finding.label}`];
  const supporting = graph.edges.filter((e) => e.to === finding.id && e.relation === 'SUPPORTS_CANDIDATE');
  for (const e of supporting) {
    const obs = graph.nodes.find((n) => n.id === e.from);
    if (obs) path.push(`Supported by observation: ${obs.label}`);
  }
  const pages = graph.nodes.filter((n) => n.type === 'PAGE');
  for (const p of pages) path.push(`Page context: ${p.label}`);
  const targets = graph.nodes.filter((n) => n.type === 'TARGET');
  for (const t of targets) path.push(`Target: ${t.label}`);
  return path;
}
