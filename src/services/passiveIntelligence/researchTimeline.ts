import crypto from 'crypto';
import { TimelineEvent, TimelineEventType } from './types.ts';

const timeline: TimelineEvent[] = [];

export function clearTimeline(): void {
  timeline.length = 0;
}

export function appendTimelineEvent(
  partial: Omit<TimelineEvent, 'id' | 'timestamp'> & { timestamp?: string }
): TimelineEvent {
  const event: TimelineEvent = {
    id: `tl-${crypto.randomBytes(5).toString('hex')}`,
    timestamp: partial.timestamp || new Date().toISOString(),
    type: partial.type,
    programId: partial.programId,
    researchCaseId: partial.researchCaseId,
    executionId: partial.executionId,
    requestId: partial.requestId,
    target: partial.target,
    details: partial.details || {},
  };
  timeline.push(event);
  return event;
}

export function getTimeline(researchCaseId?: string): TimelineEvent[] {
  // Immutable copy
  const copy = timeline.map((e) => ({ ...e, details: { ...e.details } }));
  if (!researchCaseId) return copy;
  return copy.filter((e) => e.researchCaseId === researchCaseId);
}

export function timelineTypesPresent(researchCaseId: string): TimelineEventType[] {
  return [...new Set(getTimeline(researchCaseId).map((e) => e.type))];
}
