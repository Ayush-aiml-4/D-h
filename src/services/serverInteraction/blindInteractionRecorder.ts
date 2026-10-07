import { InteractionObservation } from '../../types/serverInteractionResearch.ts';

class BlindInteractionRecorder {
  private observations: InteractionObservation[] = [];

  public recordInteraction(
    params: Omit<InteractionObservation, 'interactionId' | 'timestamp' | 'isCorrelated'> & {
      isCorrelated?: boolean;
    }
  ): InteractionObservation {
    const interactionId = `interact-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const isCorrelated = !!params.correlationToken && params.correlationToken.trim().length > 0;

    const observation: InteractionObservation = {
      interactionId,
      correlationToken: params.correlationToken || '',
      timestamp: new Date().toISOString(),
      fixtureId: params.fixtureId,
      destinationClass: params.destinationClass,
      requestedUrl: params.requestedUrl,
      method: params.method || 'GET',
      headers: params.headers || {},
      bodySnippet: params.bodySnippet,
      sourceIp: params.sourceIp || '127.0.0.1',
      isCorrelated,
    };

    this.observations.push(observation);
    return observation;
  }

  public findObservationsByToken(correlationToken: string): InteractionObservation[] {
    if (!correlationToken || !correlationToken.trim()) return [];
    return this.observations.filter(
      obs => obs.correlationToken === correlationToken.trim()
    );
  }

  public hasCorrelatedInteraction(correlationToken: string): boolean {
    return this.findObservationsByToken(correlationToken).length > 0;
  }

  public getAllObservations(): InteractionObservation[] {
    return [...this.observations];
  }

  public clear(): void {
    this.observations = [];
  }
}

export const interactionRecorder = new BlindInteractionRecorder();
