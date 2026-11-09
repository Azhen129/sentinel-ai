import type { Connection, ModelAssessment } from './types'

/** Origin labels describe evidence provenance, independently of the UI workspace. */
export function originPresentation(origin?: string, collector?: string): { label: string; tone: string; description: string } {
  if (origin === 'lab' && collector === 'localhost-lab') return { label: 'Controlled lab', tone: 'amber', description: 'This finding comes from genuine disposable localhost service activity recorded by endpoint instrumentation. It is not an Ethernet packet capture or a Zeek file import.' }
  switch (origin) {
    case 'live': return { label: 'Live Ethernet', tone: 'green', description: 'This finding comes from actual metadata observed on the selected local Ethernet interface during a bounded collection window.' }
    case 'lab': return { label: 'Lab import', tone: 'amber', description: 'This incident was generated from a passive, authorized lab file import.' }
    case 'demo': return { label: 'Synthetic', tone: 'cyan', description: 'This incident was generated from synthetic demo traffic.' }
    default: return { label: 'Unknown origin', tone: 'neutral', description: 'The API did not provide a recognized observation origin for this record.' }
  }
}

/** Unknown API state must not be presented as a synthetic or live workspace. */
export function workspacePresentation(mode?: string, publicDemo = false): { name: string; detail: string; environment: string; banner: string } {
  if (mode === 'monitor') return { name: 'Local laptop monitoring', detail: 'Ethernet metadata', environment: 'LOCAL LAPTOP · ETHERNET METADATA', banner: 'Local laptop monitoring' }
  if (mode === 'lab') return { name: 'Authorized lab', detail: 'Authorized observations', environment: 'AUTHORIZED LAB · OBSERVATIONS', banner: 'Authorized lab workspace' }
  if (mode === 'demo') return { name: publicDemo ? 'Public demonstration' : 'Demo workspace', detail: publicDemo ? 'Synthetic · read-only' : 'Isolated environment', environment: publicDemo ? 'PUBLIC DEMO · SYNTHETIC · READ-ONLY' : 'DEMO ENVIRONMENT', banner: publicDemo ? 'Read-only public demonstration' : 'Safe demonstration mode' }
  return { name: 'Connecting workspace', detail: 'Awaiting API configuration', environment: 'WORKSPACE NOT YET VERIFIED', banner: 'Waiting for workspace information' }
}

export function simulationControlsAllowed(mode?: string, publicDemo = false, permitted?: boolean): boolean {
  return !publicDemo && permitted !== false && replayControlsAllowed(mode)
}

export function incidentWritesAllowed(publicDemo = false, permitted?: boolean): boolean {
  return !publicDemo && permitted !== false
}

/** Receiving is API ingest recency. It does not establish that capture is running. */
export function monitoringStatusText(status?: string): string {
  switch (status) {
    case 'receiving': return 'Metadata received recently'
    case 'stale': return 'No recent metadata'
    case 'waiting': return 'Waiting for metadata'
    case 'disabled': return 'Monitoring disabled'
    default: return 'Observation status unavailable'
  }
}

export function replayControlsAllowed(mode?: string): boolean {
  return mode === 'demo' || mode === 'lab'
}

/** An explicit unavailable assessment must not turn into an invented zero score. */
export function baselineScore(record: Pick<Connection, 'analysis' | 'model_assessment' | 'anomaly_score'>): number | null {
  const assessment = record.analysis?.model_assessment ?? record.model_assessment
  const score = assessment ? assessment.score : record.anomaly_score
  return typeof score === 'number' && Number.isFinite(score) ? score : null
}

export function modelNumber(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(6) : 'Not available'
}

export function thresholdSourceText(assessment?: ModelAssessment): string {
  switch (assessment?.threshold_source) {
    case 'stored_at_ingest': return 'Threshold saved at ingest'
    case 'current_baseline_reference': return 'Current preserved baseline reference; not a recorded historical threshold'
    default: return 'Threshold provenance unavailable'
  }
}

export function scoreSourceText(assessment?: ModelAssessment): string {
  switch (assessment?.score_source) {
    case 'computed_at_ingest': return 'Score computed and saved at ingest'
    case 'stored_connection': return 'Original saved connection score; not rescored for this view'
    default: return 'Score provenance unavailable'
  }
}

export function findingLabel(record: Pick<Connection, 'origin' | 'is_anomaly'>, monitorMode = false): string {
  if (monitorMode || record.origin === 'live') return record.is_anomaly ? 'Saved finding' : 'No live finding'
  return record.is_anomaly ? 'Anomalous' : 'No alert'
}
