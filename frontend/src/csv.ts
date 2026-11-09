import type { Connection } from './types'

/** Escape CSV text and neutralize spreadsheet formulas from imported lab fields. */
export function csvCell(value: unknown): string {
  const text = String(value ?? '')
  const safe = typeof value === 'string' && /^\s*[=+\-@\t\r]/.test(text) ? `'${text}` : text
  return `"${safe.replace(/"/g, '""')}"`
}


/** Keep exported evidence interpretable outside the dashboard. No private adapter GUID is exported. */
export function connectionCsv(records: Connection[]): string {
  const fields: (keyof Connection)[] = ['timestamp', 'origin', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'duration', 'bytes_sent', 'bytes_received', 'status', 'service', 'is_anomaly', 'anomaly_score']
  const evidenceFields = ['collector', 'collection_id', 'flow_id', 'observation_scope', 'measurement_semantics', 'flow_semantics', 'first_seen', 'last_seen', 'window_end', 'local_role', 'score_role', 'comparison_threshold', 'threshold_source']
  const rows = records.map(record => {
    const p = record.provenance
    const assessment = record.analysis?.model_assessment ?? record.model_assessment
    const score = assessment ? assessment.score : record.anomaly_score
    const scoreRole = typeof score !== 'number' || !Number.isFinite(score) ? 'score not reported' : record.origin === 'live' ? 'informational historical baseline; not attack probability' : assessment?.alert_eligible === false ? 'informational only; not attack probability' : 'uncalibrated outlier score; not attack probability'
    const values = [p?.collector, p?.collection_id, p?.flow_id, p?.observation_scope, p?.measurement_semantics, p?.flow_semantics, p?.first_seen, p?.last_seen, p?.window_end, p?.local_role, scoreRole, assessment?.threshold, assessment?.threshold_source]
    return [...fields.map(field => record[field]), ...values].map(csvCell).join(',')
  })
  return [[...fields, ...evidenceFields].join(','), ...rows].join('\r\n')
}
