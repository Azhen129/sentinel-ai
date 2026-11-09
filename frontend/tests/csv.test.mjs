import assert from 'node:assert/strict'
import test from 'node:test'
import { connectionCsv, csvCell } from '../src/csv.ts'

test('CSV neutralizes imported spreadsheet formulas while retaining numeric measurements', () => {
  for (const value of ['=SUM(A1)', '+cmd', '-cmd', '@cmd', '\tcmd', '\rcmd', '  =1', ' \tcmd']) {
    assert.equal(csvCell(value), `"'${value}"`)
  }
  assert.equal(csvCell(-42), '"-42"')
  assert.equal(csvCell('a,"b"'), '"a,""b"""')
  assert.equal(csvCell(null), '""')
})

test('export keeps observed lineage and score caveats without private adapter identifiers', () => {
  const csv = connectionCsv([{
    timestamp: '2026-11-07T00:00:00Z', origin: 'live', src_ip: '192.0.2.10', dst_ip: '198.51.100.20',
    src_port: 50000, dst_port: 443, protocol: 'tcp', duration: 1, bytes_sent: 12, bytes_received: 34,
    status: 'observed', service: '=untrusted', is_anomaly: false, anomaly_score: 0.613,
    provenance: { collector: 'tshark', collection_id: 'public-test-collection', flow_id: 'public-test-flow', measurement_semantics: 'transport_payload_bytes', observation_scope: 'selected_interface_passive', interface_id: 'must-not-export' },
    analysis: { model_assessment: { score: 0.613, threshold: 0.593, threshold_source: 'current_baseline_reference' } },
  }])
  assert.match(csv, /collection_id,flow_id,observation_scope,measurement_semantics/)
  assert.match(csv, /public-test-collection/)
  assert.match(csv, /public-test-flow/)
  assert.match(csv, /informational historical baseline; not attack probability/)
  assert.match(csv, /current_baseline_reference/)
  assert.match(csv, /"'=untrusted"/)
  assert.doesNotMatch(csv, /interface_id|must-not-export/)
})

test('controlled records without model inference do not acquire an invented score or threshold', () => {
  const csv = connectionCsv([{
    origin: 'lab', anomaly_score: null,
    provenance: { collector: 'localhost-lab', measurement_semantics: 'application_bytes' },
    analysis: { protocol_context: { label: 'Owned service' } },
  }])
  assert.match(csv, /localhost-lab/)
  assert.match(csv, /application_bytes/)
  assert.match(csv, /"score not reported","",""/)
  assert.doesNotMatch(csv, /0\.000000|informational historical baseline/)
})
