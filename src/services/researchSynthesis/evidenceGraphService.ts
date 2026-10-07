import crypto from 'crypto';
import {
  ResearchObservation,
  EvidenceGraph,
  EvidenceGraphNode,
  EvidenceGraphEdge,
} from '../../types/researchSynthesis.ts';

export function buildEvidenceGraph(observations: ResearchObservation[]): EvidenceGraph {
  const nodesMap = new Map<string, EvidenceGraphNode>();
  const edges: EvidenceGraphEdge[] = [];

  const addNode = (node: EvidenceGraphNode) => {
    if (!nodesMap.has(node.id)) {
      nodesMap.set(node.id, node);
    }
  };

  const addEdge = (edge: EvidenceGraphEdge) => {
    // Avoid duplicate edges
    const exists = edges.some(
      (e) => e.source === edge.source && e.target === edge.target && e.type === edge.type
    );
    if (!exists) {
      edges.push(edge);
    }
  };

  // Process each observation to extract graph nodes and relations
  observations.forEach((obs, index) => {
    // 1. Observation Node
    const obsNodeId = `node-obs-${obs.observationId}`;
    addNode({
      id: obsNodeId,
      type: 'OBSERVATION',
      label: `Observation: ${obs.observationType}`,
      properties: {
        observationId: obs.observationId,
        type: obs.observationType,
        target: obs.target,
        confidence: obs.confidence,
        provenance: obs.provenance,
      },
    });

    // 2. Actor Node
    const actorId = obs.actorContext.accountIdentifier || obs.actorContext.researcherId || 'anonymous';
    const actorNodeId = `node-actor-${actorId}`;
    addNode({
      id: actorNodeId,
      type: 'ACTOR',
      label: `Actor: ${actorId} (${obs.actorContext.accountRole || 'USER'})`,
      properties: {
        identifier: actorId,
        role: obs.actorContext.accountRole,
        credentialRef: obs.actorContext.indirectCredentialRef,
      },
    });
    addEdge({
      id: `edge-actor-${actorNodeId}-${obsNodeId}`,
      source: actorNodeId,
      target: obsNodeId,
      type: 'AUTHORIZES',
      reason: 'Actor executed observation test',
    });

    // 3. Resource Node
    if (obs.resourceIdentifier) {
      const resNodeId = `node-res-${obs.resourceIdentifier}`;
      addNode({
        id: resNodeId,
        type: 'RESOURCE',
        label: `Resource: ${obs.resourceIdentifier}`,
        properties: {
          identifier: obs.resourceIdentifier,
          target: obs.target,
          asset: obs.asset,
        },
      });
      addEdge({
        id: `edge-obs-res-${obsNodeId}-${resNodeId}`,
        source: obsNodeId,
        target: resNodeId,
        type: 'AFFECTS',
        reason: 'Observation affects resource',
      });
    }

    // 4. Evidence Nodes
    obs.evidenceReferences.forEach((evRef) => {
      const evNodeId = `node-ev-${evRef}`;
      const evHash = crypto.createHash('sha256').update(evRef).digest('hex');
      addNode({
        id: evNodeId,
        type: 'EVIDENCE',
        label: `Evidence: ${evRef.substring(0, 24)}`,
        properties: {
          reference: evRef,
        },
        evidenceHash: evHash,
      });
      addEdge({
        id: `edge-ev-obs-${evNodeId}-${obsNodeId}`,
        source: evNodeId,
        target: obsNodeId,
        type: 'SUPPORTS',
        reason: 'Evidence supports observation',
      });
    });

    // 5. Action Node
    const actionNodeId = `node-act-${obs.observationId}`;
    addNode({
      id: actionNodeId,
      type: 'ACTION',
      label: `Action: ${obs.capability}`,
      properties: {
        capability: obs.capability,
        engine: obs.provenance.engine,
      },
    });
    addEdge({
      id: `edge-act-obs-${actionNodeId}-${obsNodeId}`,
      source: actionNodeId,
      target: obsNodeId,
      type: 'DERIVED_FROM',
    });

    // 6. Impact Nodes
    obs.impactIndicators.forEach((ind) => {
      const impNodeId = `node-imp-${ind.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
      addNode({
        id: impNodeId,
        type: 'IMPACT',
        label: `Impact: ${ind}`,
        properties: { indicator: ind },
      });
      addEdge({
        id: `edge-obs-imp-${obsNodeId}-${impNodeId}`,
        source: obsNodeId,
        target: impNodeId,
        type: 'VIOLATES',
        reason: `Observation produces impact: ${ind}`,
      });
    });

    // 7. Workflow / Sequence Edges (PRECEDES)
    if (index > 0) {
      const prevObs = observations[index - 1];
      if (
        prevObs.researchCaseId === obs.researchCaseId &&
        (prevObs.workflowId === obs.workflowId || prevObs.resourceIdentifier === obs.resourceIdentifier)
      ) {
        addEdge({
          id: `edge-seq-${prevObs.observationId}-${obs.observationId}`,
          source: `node-obs-${prevObs.observationId}`,
          target: obsNodeId,
          type: 'PRECEDES',
          reason: 'Sequential step execution in workflow/resource lineage',
        });
      }
    }
  });

  return {
    nodes: Array.from(nodesMap.values()),
    edges,
  };
}
