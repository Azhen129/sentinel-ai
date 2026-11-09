import assert from 'node:assert/strict'
import test from 'node:test'
import { baselineScore, findingLabel, incidentWritesAllowed, modelNumber, monitoringStatusText, originPresentation, replayControlsAllowed, scoreSourceText, simulationControlsAllowed, thresholdSourceText, workspacePresentation } from '../src/presentation.ts'

test('live evidence is never presented as synthetic or as a file import', () => {
  const live = originPresentation('live')
  assert.equal(live.label, 'Live Ethernet')
  assert.match(live.description, /actual metadata observed/)
  assert.doesNotMatch(live.description, /synthetic|file import/)
  assert.equal(originPresentation('demo').label, 'Synthetic')
  assert.equal(originPresentation('lab').label, 'Lab import')
})

test('unrecognized provenance does not silently become synthetic', () => {
  for (const origin of [undefined, '', 'future-source']) {
    assert.equal(originPresentation(origin).label, 'Unknown origin')
  }
})

test('ingest recency never claims that a collector is capturing', () => {
  assert.equal(monitoringStatusText('receiving'), 'Metadata received recently')
  assert.equal(monitoringStatusText('waiting'), 'Waiting for metadata')
  assert.equal(monitoringStatusText('stale'), 'No recent metadata')
  assert.equal(monitoringStatusText('disabled'), 'Monitoring disabled')
  for (const status of ['receiving', 'waiting', 'stale', 'disabled', undefined]) {
    assert.doesNotMatch(monitoringStatusText(status), /captur|running|protected/i)
  }
})

test('monitor and unknown workspaces do not expose replay actions', () => {
  assert.equal(replayControlsAllowed('monitor'), false)
  assert.equal(replayControlsAllowed(undefined), false)
  assert.equal(replayControlsAllowed('future-mode'), false)
  assert.equal(replayControlsAllowed('demo'), true)
  assert.equal(replayControlsAllowed('lab'), true)
})

test('current model reference is not represented as a saved historical threshold', () => {
  assert.equal(thresholdSourceText({ threshold_source: 'stored_at_ingest' }), 'Threshold saved at ingest')
  assert.match(thresholdSourceText({ threshold_source: 'current_baseline_reference' }), /not a recorded historical threshold/)
  assert.equal(thresholdSourceText(), 'Threshold provenance unavailable')
  assert.match(scoreSourceText({ score_source: 'stored_connection' }), /not rescored/)
})

test('missing model values are not formatted as zero or probabilities', () => {
  assert.equal(modelNumber(null), 'Not available')
  assert.equal(modelNumber(undefined), 'Not available')
  assert.equal(modelNumber(NaN), 'Not available')
  assert.equal(modelNumber(0), '0.000000')
  assert.equal(modelNumber(0.613), '0.613000')
})

test('explicit unavailable live assessment overrides an old numeric score', () => {
  const record = { anomaly_score: 0.613, analysis: { model_assessment: { score: null } } }
  assert.equal(baselineScore(record), null)
  assert.equal(baselineScore({ anomaly_score: 0.613 }), 0.613)
  assert.equal(baselineScore({ anomaly_score: 0, model_assessment: { score: 0.614 } }), 0.614)
  assert.equal(baselineScore({ anomaly_score: Infinity }), null)
})

test('live saved findings and absent findings are not attack or benign verdicts', () => {
  assert.equal(findingLabel({ origin: 'live', is_anomaly: true }), 'Saved finding')
  const absent = findingLabel({ origin: 'live', is_anomaly: false })
  assert.equal(absent, 'No live finding')
  assert.doesNotMatch(absent, /safe|benign|normal|protected/i)
  assert.equal(findingLabel({ origin: 'demo', is_anomaly: true }), 'Anomalous')
  assert.equal(findingLabel({ origin: 'lab', is_anomaly: false }), 'No alert')
})

test('unknown workspace information never defaults to demo or real Ethernet', () => {
  for (const mode of [undefined, '', 'future-mode']) {
    const state = workspacePresentation(mode)
    assert.equal(state.environment, 'WORKSPACE NOT YET VERIFIED')
    assert.doesNotMatch(state.name, /demo|Ethernet/i)
  }
  assert.match(workspacePresentation('demo').environment, /DEMO/)
  assert.match(workspacePresentation('monitor').environment, /ETHERNET/)
})

test('public demo and explicitly denied capabilities disable all mutation controls', () => {
  assert.equal(simulationControlsAllowed('demo', true, true), false)
  assert.equal(simulationControlsAllowed('demo', false, false), false)
  assert.equal(simulationControlsAllowed('demo'), true)
  assert.equal(simulationControlsAllowed('monitor'), false)
  assert.equal(incidentWritesAllowed(true, true), false)
  assert.equal(incidentWritesAllowed(false, false), false)
  assert.equal(incidentWritesAllowed(), true)
  assert.match(workspacePresentation('demo', true).banner, /Read-only public demonstration/)
})

test('controlled endpoint evidence cannot be mislabeled as an Ethernet capture or file import', () => {
  const controlled = originPresentation('lab', 'localhost-lab')
  assert.equal(controlled.label, 'Controlled lab')
  assert.match(controlled.description, /endpoint instrumentation/)
  assert.match(controlled.description, /not an Ethernet packet capture or a Zeek file import/)
  assert.equal(originPresentation('lab').label, 'Lab import')
  assert.equal(originPresentation('live', 'tshark').label, 'Live Ethernet')
})
