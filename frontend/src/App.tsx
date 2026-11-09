import { useCallback, useDeferredValue, useEffect, useRef, useState, type ReactNode } from 'react'
import { Activity, ArrowDownLeft, ArrowRight, ArrowUpRight, Bell, BookOpen, BrainCircuit, Cable, Check, ChevronDown, ChevronLeft, ChevronRight, Circle, CircleCheck, Clock3, Cpu, Database, Download, ExternalLink, FileText, Filter, FlaskConical, Info, LayoutDashboard, LoaderCircle, Menu, Network, Pause, Play, Radar, RefreshCw, RotateCcw, Search, Send, Server, Shield, ShieldAlert, SlidersHorizontal, Upload, X, type LucideIcon } from 'lucide-react'
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, bytes, compact, date, num, percentage, time } from './api'
import { connectionCsv } from './csv'
import { baselineScore, findingLabel, incidentWritesAllowed, modelNumber, monitoringStatusText, originPresentation, scoreSourceText, simulationControlsAllowed, thresholdSourceText, workspacePresentation } from './presentation'
import type { Connection, Incident, ModelInfo, MonitoringInfo, Overview, RecordOrigin, Simulation, SystemInfo } from './types'

type Page = 'overview' | 'traffic' | 'incidents' | 'model' | 'system'
const pages: { id: Page; label: string; icon: LucideIcon; subtitle: string }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard, subtitle: 'Your network, in focus.' },
  { id: 'traffic', label: 'Traffic explorer', icon: Network, subtitle: 'Follow every connection.' },
  { id: 'incidents', label: 'Incidents', icon: ShieldAlert, subtitle: 'Turn signals into understanding.' },
  { id: 'model', label: 'AI model', icon: BrainCircuit, subtitle: 'Understand the intelligence.' },
  { id: 'system', label: 'System health', icon: Server, subtitle: 'Know what is running.' },
]
const colors = ['#42d5c1', '#658ff1', '#b099ee', '#d2ae63', '#788a9d']
const initialSim: Simulation = { status: 'idle', processed: 0, total: 0, speed: 1 }
const validPage = (hash: string): Page => pages.some(p => p.id === hash) ? hash as Page : 'overview'
const asRecord = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
const display = (value: unknown): string => value === undefined || value === null ? 'Not available' : typeof value === 'object' ? JSON.stringify(value) : String(value)
const numeric = (value: unknown): number | undefined => typeof value === 'number' ? value : undefined
const incidentRef = (value: string | number): string => String(value).startsWith('INC-') ? String(value) : `INC-${String(value).padStart(4, '0')}`
const historyTitle = (action?: string): string => ({ detected: 'Detection created', status_changed: 'Status updated', status: 'Status updated', note: 'Investigation note', correlated: 'Detection correlated' } as Record<string, string>)[action ?? ''] ?? (action ?? 'Incident event').replace(/_/g, ' ')

function Logo({ small = false }: { small?: boolean }) { return <div className={`brand ${small ? 'brand-small' : ''}`}><div className="brand-symbol"><Shield size={29} strokeWidth={1.6} /><span className="brand-symbol-core" /></div>{!small && <div className="brand-name">sentinel<span>AI</span><small>SECURITY OPERATIONS</small></div>}</div> }
function Badge({ children, tone = 'neutral', dot = false }: { children: ReactNode; tone?: string; dot?: boolean }) { return <span className={`badge badge-${tone}`}>{dot && <span className="status-dot" />}{children}</span> }
function Source({ value, origin }: { value: string; origin?: RecordOrigin }) { return <span className={`source-label ${value === 'ml' ? 'source-ai' : ''}`}>{value === 'ml' ? <BrainCircuit size={12} /> : <SlidersHorizontal size={12} />}{value === 'ml' ? origin === 'live' ? 'Baseline ML' : 'AI anomaly' : 'Detection rule'}</span> }
function OriginBadge({ value, collector, genericLab = false }: { value?: RecordOrigin; collector?: string; genericLab?: boolean }) { const origin = originPresentation(value, collector); return <Badge tone={origin.tone}>{value === 'live' && <Cable size={10} />}{value === 'lab' && genericLab && !collector ? 'Authorized lab' : origin.label}</Badge> }
function Empty({ icon: Icon = Radar, title, children }: { icon?: LucideIcon; title: string; children: ReactNode }) { return <div className="empty-state"><Icon size={30} strokeWidth={1.3} /><h3>{title}</h3><p>{children}</p></div> }
function SectionHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) { return <div className="section-header"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div> }

function App() {
  const [page, setPage] = useState<Page>(() => validPage(window.location.hash.slice(1)))
  const [overview, setOverview] = useState<Overview | null>(null)
  const [connections, setConnections] = useState<Connection[]>([])
  const [connectionTotal, setConnectionTotal] = useState(0)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [incidentTotal, setIncidentTotal] = useState(0)
  const [model, setModel] = useState<ModelInfo>({})
  const [system, setSystem] = useState<SystemInfo>({})
  const [error, setError] = useState('')
  const [actionError, setActionError] = useState('')
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshToken, setRefreshToken] = useState(0)
  const [busyAction, setBusyAction] = useState('')
  const [speed, setSpeed] = useState(4)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [search, setSearch] = useState('')
  const query = useDeferredValue(search)
  const [protocol, setProtocol] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [source, setSource] = useState('')
  const [offset, setOffset] = useState(0)
  const [selectedId, setSelectedId] = useState<string | number | null>(null)
  const [showReset, setShowReset] = useState(false)
  const [loadedKey, setLoadedKey] = useState('')
  const sidebarRef = useRef<HTMLElement>(null)
  const requestKey = JSON.stringify([page, query, protocol, severity, status, source, offset])
  const resultsReady = loadedKey === requestKey && (!(page === 'traffic' || page === 'incidents') || query === search)
  const refresh = useCallback(() => setRefreshToken(t => t + 1), [])

  useEffect(() => { const handler = () => setPage(validPage(window.location.hash.slice(1))); window.addEventListener('hashchange', handler); return () => window.removeEventListener('hashchange', handler) }, [])
  useEffect(() => { setSearch(''); setOffset(0); setMobileOpen(false) }, [page])
  useEffect(() => { setOffset(0) }, [query, protocol])
  useEffect(() => {
    if (!mobileOpen) return
    const original = document.activeElement as HTMLElement | null
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    sidebarRef.current?.querySelector<HTMLElement>('a, button')?.focus()
    const resize = () => { if (window.innerWidth > 820) setMobileOpen(false) }
    window.addEventListener('resize', resize)
    return () => { document.body.style.overflow = overflow; original?.focus(); window.removeEventListener('resize', resize) }
  }, [mobileOpen])
  useEffect(() => {
    let disposed = false
    let fetching = false
    const abort = new AbortController()
    const fetchAll = async () => {
      if (fetching) return
      fetching = true
      try {
        const options = { signal: abort.signal }
        const data = await api<Overview>('/overview', options)
        if (disposed) return
        setOverview(data); setLastUpdated(new Date()); setError(''); setLoading(false)
        if (page === 'traffic') {
          const params = new URLSearchParams({ q: query, protocol, offset: String(offset), limit: '50' })
          const result = await api<{ items: Connection[]; total: number }>(`/connections?${params}`, options)
          if (!disposed) { setConnections(result.items); setConnectionTotal(result.total) }
        } else if (page === 'incidents') {
          const params = new URLSearchParams({ q: query, severity, status, source, limit: '100' })
          const result = await api<{ items: Incident[]; total: number }>(`/incidents?${params}`, options)
          if (!disposed) { setIncidents(result.items); setIncidentTotal(result.total) }
        } else if (page === 'model') {
          const result = await api<ModelInfo>('/model', options); if (!disposed) setModel(result)
        } else if (page === 'system') {
          const result = await api<SystemInfo>('/system', options); if (!disposed) setSystem(result)
        }
        if (!disposed) setLoadedKey(requestKey)
      } catch (err) { if (!disposed) { setError(err instanceof Error ? err.message : 'The API could not be reached.'); setLoading(false) } }
      finally { fetching = false }
    }
    void fetchAll()
    const timer = window.setInterval(fetchAll, 2000)
    return () => { disposed = true; abort.abort(); window.clearInterval(timer) }
  }, [page, query, protocol, severity, status, source, offset, refreshToken, requestKey])

  const simulation = overview?.simulation ?? initialSim
  const navigate = (next: Page) => { window.location.hash = next; setPage(next) }
  const action = async (name: 'start' | 'pause' | 'reset') => {
    if (!simulationControlsAllowed(overview?.mode, overview?.public_demo, overview?.capabilities?.simulation_control)) return
    setBusyAction(name); setActionError('')
    try { const result = await api<Simulation>(`/simulation/${name}`, { method: 'POST', body: JSON.stringify(name === 'start' ? { speed } : {}) }); setOverview(old => old ? { ...old, simulation: result } : old); setShowReset(false); refresh() }
    catch (err) { setActionError(err instanceof Error ? err.message : 'Action failed. Please try again.') }
    finally { setBusyAction('') }
  }
  const currentPage = pages.find(p => p.id === page)!
  const progress = simulation.total ? Math.min(simulation.processed / simulation.total * 100, 100) : 0
  const labMode = overview?.mode === 'lab'
  const monitorMode = overview?.mode === 'monitor'
  const knownMode = ['demo', 'lab', 'monitor'].includes(overview?.mode ?? '')
  const workspace = workspacePresentation(overview?.mode, overview?.public_demo)
  const replayAllowed = simulationControlsAllowed(overview?.mode, overview?.public_demo, overview?.capabilities?.simulation_control)
  const writeAllowed = incidentWritesAllowed(overview?.public_demo, overview?.capabilities?.incident_write)
  const demoRecords = overview?.data_sources?.demo ?? (overview?.mode === 'demo' ? overview.total_connections : 0)
  const labRecords = overview?.data_sources?.lab ?? 0
  const liveRecords = overview?.data_sources?.live ?? 0
  const mixedSources = [demoRecords, labRecords, liveRecords].filter(count => count > 0).length > 1
  const dataLabel = !knownMode ? 'PROVENANCE UNAVAILABLE' : mixedSources ? 'MIXED SOURCES' : liveRecords > 0 ? 'ACTUAL OBSERVED METADATA' : labRecords > 0 ? 'AUTHORIZED LAB RECORDS' : monitorMode ? 'WAITING FOR METADATA' : labMode ? 'WAITING FOR LAB RECORDS' : 'SYNTHETIC DATA'

  return <div className="app-shell">
    {mobileOpen && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    <aside id="workspace-navigation" ref={sidebarRef} className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`} role={mobileOpen ? 'dialog' : undefined} aria-modal={mobileOpen ? true : undefined} aria-label={mobileOpen ? 'Workspace navigation' : undefined} onKeyDown={event => { if (mobileOpen) { if (event.key === 'Escape') setMobileOpen(false); trapFocus(event, sidebarRef.current) } }}>
      <a href="#overview" className="brand-link" aria-label="Sentinel AI overview"><Logo /></a>
      <div className="workspace-switch"><div className="workspace-icon"><FlaskConical size={17} /></div><div><strong>{workspace.name}</strong><span>{workspace.detail}</span></div><ChevronDown size={14} /></div>
      <div className="nav-caption">WORKSPACE</div>
      <nav aria-label="Main navigation">{pages.map(item => <button key={item.id} className={`nav-item ${page === item.id ? 'active' : ''}`} onClick={() => navigate(item.id)} aria-current={page === item.id ? 'page' : undefined}><item.icon size={18} strokeWidth={1.7} /><span>{item.label}</span>{item.id === 'incidents' && (overview?.active_incidents ?? 0) > 0 && <span className="nav-count">{num(overview!.active_incidents)}</span>}{page === item.id && <span className="nav-active-dot" />}</button>)}</nav>
      <div className="sidebar-spacer" />
      <div className="sidebar-lab"><div className="lab-icon"><Shield size={18} /></div><strong>{!knownMode ? 'Workspace not yet verified' : monitorMode ? 'Local interface view' : labMode ? 'Authorized lab evidence' : 'Built for safe exploration'}</strong><p>{!knownMode ? <>Source and mode appear after the API responds.</> : monitorMode ? <>Observed Ethernet metadata.<br />Visibility is limited to this laptop.</> : labMode ? <>Authorized observations labeled by source.<br />No capture starts from this dashboard.</> : <>Synthetic traffic. Real detection.<br />No access to your network.</>}</p><button onClick={() => navigate('system')}>Explore the environment <ArrowUpRight size={13} /></button></div>
      <div className="sidebar-footer"><span className={`connection-dot ${error ? 'offline' : lastUpdated ? '' : 'waiting'}`} /><span>{error ? 'API unavailable' : lastUpdated ? 'API connected' : 'Connecting…'}</span><code>v1.0.0</code></div>
    </aside>
    <main className="main-shell">
      <header className="topbar"><div className="breadcrumb"><button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation" aria-expanded={mobileOpen} aria-controls="workspace-navigation"><Menu size={20} /></button><span>Workspace</span><ChevronRight size={13} /><strong>{currentPage.label}</strong></div><div className="topbar-right"><span className="environment-label"><span />{workspace.environment}</span><button className="icon-button notification-button" aria-label="View incidents" onClick={() => navigate('incidents')}><Bell size={18} />{(overview?.active_incidents ?? 0) > 0 && <i />}</button><div className="avatar" title="Local analyst workspace">SA</div></div></header>
      <div className="page-content">
        <div className="page-heading"><div><div className="eyebrow">SENTINEL INTELLIGENCE PLATFORM</div><h1>{page === 'overview' ? 'Security overview' : currentPage.label}</h1><p>{monitorMode ? 'Review actual metadata observed on this laptop’s selected Ethernet interface.' : currentPage.subtitle}</p></div><div className="heading-right"><span className={`live-indicator ${error || !knownMode ? 'muted' : ''}`}><span />{error ? 'Connection interrupted' : !knownMode ? 'Waiting for workspace' : overview?.public_demo ? 'Read-only synthetic snapshot' : monitorMode ? monitoringStatusText(overview?.monitoring?.status) : simulation.status === 'running' ? 'Replay running' : 'Replay not running'}</span><span className="last-updated">{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}` : 'Waiting for backend'}</span></div></div>
        <section className="demo-banner" aria-label={monitorMode ? 'Local observation provenance' : 'Safe demo controls'}>
          <div className="demo-banner-icon">{monitorMode ? <Cable size={20} /> : <FlaskConical size={20} />}</div>
          <div className="demo-copy"><div><strong>{workspace.banner}</strong><Badge tone={!knownMode ? 'neutral' : mixedSources ? 'amber' : monitorMode ? 'green' : 'cyan'}>{dataLabel}</Badge></div>
            {!knownMode ? <p>Record provenance and available actions will appear after the configured backend responds.</p> : overview?.public_demo ? <p>Frozen synthetic records demonstrate the application. Replay and investigation edits are disabled. This is not a live protection service.</p> : monitorMode ? <p>{num(liveRecords)} observed flow records retained. A separate local collector supplies bounded observation windows. This dashboard cannot start capture.{mixedSources && <> Other origins: {num(demoRecords)} synthetic · {num(labRecords)} lab records.</>}</p> : <p>{labMode && <>Sources: {num(demoRecords)} synthetic · {num(labRecords)} authorized lab records. Controlled endpoint events and imported logs retain their provenance. Replay uses synthetic data. </>}{simulation.status === 'running' ? `Replaying connection records · ${num(simulation.processed)} of ${num(simulation.total)} events processed` : simulation.status === 'completed' ? 'Replay complete. Investigate the findings or reset to explore again.' : labMode ? 'Review the stored observations in Traffic explorer and Incidents.' : 'Explore simulated network traffic and see the detection engine in action.'}</p>}
          </div>
          {replayAllowed && <div className="simulation-actions"><select aria-label="Replay speed" value={speed} onChange={e => setSpeed(Number(e.target.value))} disabled={simulation.status === 'running'}><option value={1}>1× speed</option><option value={4}>4× speed</option><option value={10}>10× speed</option></select><button className="icon-button reset-button" title="Reset demonstration" aria-label="Reset demonstration" onClick={() => setShowReset(true)} disabled={!!busyAction}><RotateCcw size={16} /></button><button className="button button-primary" onClick={() => void action(simulation.status === 'running' ? 'pause' : 'start')} disabled={!!busyAction || !!error || simulation.status === 'completed'}>{busyAction ? <LoaderCircle size={15} className="spin" /> : simulation.status === 'running' ? <Pause size={15} fill="currentColor" /> : <Play size={15} fill="currentColor" />}{simulation.status === 'running' ? 'Pause replay' : simulation.status === 'paused' ? 'Resume replay' : simulation.status === 'completed' ? 'Replay complete' : 'Start simulation'}</button></div>}
          {replayAllowed && simulation.status !== 'idle' && <div className="replay-progress" style={{ width: `${progress}%` }} />}
        </section>
        {(error || actionError) && <div role="alert" className="error-banner"><Info size={17} /><div><strong>{error ? 'Unable to refresh the console' : 'Action could not be completed'}</strong><span>{error || actionError}{error && ' Check that the configured local FastAPI backend is running.'}</span></div><button className="button button-subtle" onClick={() => { setActionError(''); refresh() }}>Retry <RefreshCw size={13} /></button></div>}
        {!overview ? loading ? <div className="loading-state" role="status"><LoaderCircle className="spin" size={26} /><p>Connecting to Sentinel…</p></div> : <Empty icon={Server} title="Workspace information unavailable">Retry when the configured backend is available. No record source has been verified.</Empty> : <>
          {page === 'overview' && <OverviewPage data={overview} openIncident={setSelectedId} navigate={navigate} />}
          {page === 'traffic' && <TrafficPage monitorMode={monitorMode} records={resultsReady ? connections : []} total={resultsReady ? connectionTotal : 0} loading={!resultsReady && !error} loadError={!resultsReady ? error : ''} search={search} setSearch={setSearch} protocol={protocol} setProtocol={setProtocol} offset={offset} setOffset={setOffset} />}
          {page === 'incidents' && <IncidentsPage monitorMode={monitorMode} records={resultsReady ? incidents : []} total={resultsReady ? incidentTotal : 0} loading={!resultsReady && !error} loadError={!resultsReady ? error : ''} search={search} setSearch={setSearch} severity={severity} setSeverity={setSeverity} status={status} setStatus={setStatus} source={source} setSource={setSource} openIncident={setSelectedId} />}
          {(page === 'model' || page === 'system') && !resultsReady && (error ? <Empty icon={Server} title="Page information unavailable">Use Retry above to request this view again.</Empty> : <div className="loading-state" role="status"><LoaderCircle className="spin" size={24} /><p>Loading {currentPage.label.toLowerCase()}…</p></div>)}
          {page === 'model' && resultsReady && <ModelPage monitorMode={monitorMode} model={model} />}
          {page === 'system' && resultsReady && <SystemPage system={system} onIngest={refresh} />}
        </>}
        <footer className="content-footer"><span><Shield size={12} /> Sentinel AI <span className="footer-separator">/</span> Network intelligence, explained.</span><span>{!knownMode ? 'Provenance not yet verified · ' : monitorMode ? 'Private local metadata · ' : labMode ? 'Lab evidence labeled by source · ' : 'Synthetic replay · '}All times shown in your local timezone</span></footer>
      </div>
    </main>
    {selectedId !== null && <IncidentDrawer key={selectedId} id={selectedId} close={() => setSelectedId(null)} onUpdate={refresh} readOnly={!writeAllowed} />}
    {showReset && replayAllowed && <Modal close={() => setShowReset(false)} title="Reset the demonstration?"><div className="reset-dialog-icon"><RotateCcw size={24} /></div><h2>Start with a clean slate</h2><p>This clears demo connection records, alerts, and investigation notes, then prepares a fresh replay. Export anything you want to keep first.</p><div className="dialog-actions"><button className="button button-secondary" onClick={() => setShowReset(false)}>Cancel</button><button className="button button-danger" disabled={!!busyAction} onClick={() => void action('reset')}>{busyAction ? <LoaderCircle size={15} className="spin" /> : <RotateCcw size={15} />}Reset demo</button></div></Modal>}
  </div>
}

function StatCard({ title, value, detail, icon: Icon, tone = 'cyan', footer }: { title: string; value: string; detail: string; icon: LucideIcon; tone?: string; footer: ReactNode }) {
  return <article className="stat-card"><div className="stat-top"><span>{title}</span><div className={`stat-icon stat-${tone}`}><Icon size={17} strokeWidth={1.7} /></div></div><div className="stat-value">{value}<span>{detail}</span></div><div className="stat-footer">{footer}</div></article>
}

function OverviewPage({ data, openIncident, navigate }: { data: Overview | null; openIncident: (id: string | number) => void; navigate: (page: Page) => void }) {
  const d = data
  const monitorMode = d?.mode === 'monitor'
  const totalDevices = Math.min(d?.top_devices.length ?? 0, 5)
  const maxDeviceConnections = Math.max(...(d?.top_devices.map(device => device.connections) ?? []), 1)
  const ruleDetections = d?.detection_stats.find(stat => stat.name === 'rule')?.value ?? 0
  const mlDetections = d?.detection_stats.find(stat => stat.name === 'ml')?.value ?? 0
  const unresolvedHigh = d?.recent_incidents.filter(i => (i.severity === 'high' || i.severity === 'critical') && i.status !== 'resolved').length ?? 0
  return <>
    <div className="stats-grid"><StatCard title={monitorMode ? "Observed flow records" : "Total connections"} value={num(d?.total_connections)} detail={monitorMode ? "flow records" : "connections"} icon={Network} footer={<><span className="tiny-dot cyan-dot" />{monitorMode ? "Bounded observation windows, not full sessions" : "Processed through detection pipeline"}</>} /><StatCard title="Traffic processed" value={bytes(d?.total_bytes)} detail="" icon={ArrowDownLeft} tone="blue" footer={<><span className="tiny-dot blue-dot" />{monitorMode ? "Header-derived transport payload lengths" : "Sent + received across all records"}</>} /><StatCard title="Active incidents" value={num(d?.active_incidents)} detail="to investigate" icon={ShieldAlert} tone="amber" footer={<><span className="tiny-dot amber-dot" />{unresolvedHigh ? `${unresolvedHigh} high-priority in recent alerts` : 'Open and investigating incidents'}</>} /><StatCard title={monitorMode ? "Flagged flow records" : "Anomalous traffic"} value={`${Number(d?.anomaly_rate ?? 0).toFixed(1)}%`} detail={monitorMode ? "of flow records" : "of connections"} icon={Radar} tone="purple" footer={<><span className="tiny-dot purple-dot" />{monitorMode ? "Saved findings; not a measured attack rate" : "Flagged by rules or the AI model"}</>} /></div>
    <div className="overview-chart-grid"><section className="panel traffic-panel"><SectionHeader title={monitorMode ? "Observed laptop activity" : "Network activity"} subtitle={monitorMode ? "Flow records and saved findings by observation time" : "Connection volume and detected anomalies over time"} action={<Badge><Clock3 size={11} />{monitorMode ? "Observation timeline" : "Replay timeline"}</Badge>} /><div className="chart-legend"><span><i style={{ background: colors[0] }} />{monitorMode ? "Flow records" : "Connections"}</span><span><i style={{ background: '#edb566' }} />{monitorMode ? 'Saved findings' : 'Anomalies'}</span></div><div className="traffic-chart">{d?.traffic.length ? <ResponsiveContainer width="100%" height="100%"><AreaChart data={d.traffic} margin={{ top: 12, right: 8, left: -24, bottom: 3 }}><defs><linearGradient id="traffic-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#42d5c1" stopOpacity={0.19} /><stop offset="100%" stopColor="#42d5c1" stopOpacity={0.01} /></linearGradient><linearGradient id="anomaly-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#edb566" stopOpacity={0.1} /><stop offset="100%" stopColor="#edb566" stopOpacity={0} /></linearGradient></defs><CartesianGrid vertical={false} stroke="#1d2937" strokeDasharray="3 5" /><XAxis dataKey="timestamp" tickFormatter={v => time(String(v)).slice(0, 5)} tick={{ fill: '#76859a', fontSize: 11 }} minTickGap={30} axisLine={false} tickLine={false} dy={10} /><YAxis tick={{ fill: '#76859a', fontSize: 11 }} allowDecimals={false} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: '#121d2b', border: '1px solid #2b3b4f', borderRadius: 9, color: '#dce5f2', fontSize: 12 }} labelFormatter={v => date(String(v))} /><Area type="monotone" dataKey="connections" name={monitorMode ? "Observed flow records" : "Connections"} stroke="#42d5c1" strokeWidth={2} fill="url(#traffic-fill)" isAnimationActive={false} /><Area type="monotone" dataKey="anomalies" name={monitorMode ? "Saved findings" : "Anomalies"} stroke="#edb566" strokeWidth={1.5} fill="url(#anomaly-fill)" isAnimationActive={false} /></AreaChart></ResponsiveContainer> : <Empty title={monitorMode ? "Waiting for observed metadata" : "Your timeline starts here"}>{monitorMode ? "An explicitly started local collector supplies bounded Ethernet observation windows. This dashboard cannot start collection." : "Start the simulation to see traffic flow through the detection pipeline."}</Empty>}</div><div className="chart-footnote"><span><Circle size={10} /> {monitorMode ? "Bounded observations; metadata arrives after each collection window" : "Aggregated from processed connection timestamps"}</span><button className="text-button" onClick={() => navigate('traffic')}>Explore traffic <ArrowRight size={13} /></button></div></section>
    <section className="panel protocol-panel"><SectionHeader title="Traffic composition" subtitle="Distribution by network protocol" /><div className="donut-wrap">{d?.protocols.length ? <><ResponsiveContainer width="100%" height={190}><PieChart><Pie data={d.protocols} dataKey="value" nameKey="name" innerRadius={62} outerRadius={79} paddingAngle={4} stroke="transparent" isAnimationActive={false}>{d.protocols.map((p, index) => <Cell key={p.name} fill={colors[index % colors.length]} />)}</Pie><Tooltip contentStyle={{ background: '#121d2b', border: '1px solid #2b3b4f', borderRadius: 8, color: '#dce5f2', fontSize: 12 }} itemStyle={{ color: '#dce5f2' }} formatter={v => [num(Number(v)), monitorMode ? 'Flow records' : 'Connections']} /></PieChart></ResponsiveContainer><div className="donut-center"><strong>{compact(d.total_connections)}</strong><span>{monitorMode ? "FLOW RECORDS" : "CONNECTIONS"}</span></div></> : <Empty title="No protocols yet">{monitorMode ? "Protocol composition will appear after actual metadata is received." : "Replay traffic to see its composition."}</Empty>}</div><div className="protocol-legend">{d?.protocols.map((p, i) => <div key={p.name}><span><i style={{ background: colors[i % colors.length] }} />{p.name.toUpperCase()}</span><strong>{num(p.value)}<small>{d.total_connections ? Math.round(p.value / d.total_connections * 100) : 0}%</small></strong></div>)}</div></section></div>
    <div className="overview-bottom-grid"><section className="panel alert-panel"><SectionHeader title={monitorMode ? "Saved incidents" : "Latest security alerts"} subtitle={monitorMode ? "Historical findings retain their original saved priority" : "Correlated findings from the detection pipeline"} action={<button className="text-button" onClick={() => navigate('incidents')}>View all incidents <ArrowRight size={13} /></button>} />{d?.recent_incidents.length ? <div className="alert-feed">{d.recent_incidents.slice(0, 5).map(i => <button className="alert-row" key={i.id} onClick={() => openIncident(i.id)}><div className={`alert-icon severity-${i.severity}`}><ShieldAlert size={17} strokeWidth={1.6} /></div><div className="alert-main"><div><strong>{i.title}</strong><Badge tone={i.severity}>{i.severity}</Badge></div><p><code>{i.src_ip}</code><ArrowRight size={11} /><code>{i.dst_ip}</code><span className="alert-event-count">{num(i.count)} events</span></p></div><div className="alert-meta"><Source value={i.detection_source} origin={i.origin} /><time dateTime={i.last_seen || i.timestamp} title={i.last_seen || i.timestamp}>{time(i.last_seen || i.timestamp)}</time></div><ChevronRight className="row-arrow" size={15} /></button>)}</div> : <Empty title="No alerts to investigate">{monitorMode ? "Findings from observed metadata will appear with their indicators. An anomaly alone is not proof of an attack." : "Suspicious replay activity will appear here with the indicators that triggered it."}</Empty>}<div className="panel-bottom detection-breakdown"><span><Source value="rule" /><strong>{num(ruleDetections)}</strong> incidents</span><span><Source value="ml" origin={monitorMode ? "live" : undefined} /><strong>{num(mlDetections)}</strong> incidents</span><small>All stored incidents, including resolved</small></div></section>
    <section className="panel talkers-panel"><SectionHeader title={monitorMode ? "Observed source addresses" : "Top communicating devices"} subtitle={`${num(totalDevices)} most active source addresses`} /><div className="talker-table-head"><span>SOURCE ADDRESS</span><span>{monitorMode ? "FLOW RECORDS" : "CONNECTIONS"}</span></div>{d?.top_devices.length ? <div className="talker-list">{d.top_devices.slice(0, 5).map((device, i) => <div className="talker" key={device.ip}><div className="talker-line"><span className="device-number">{String(i + 1).padStart(2, '0')}</span><code>{device.ip}</code><strong>{num(device.connections)}</strong></div><div className="talker-bar"><span style={{ width: `${Math.min(device.connections / maxDeviceConnections * 100, 100)}%`, opacity: 1 - i * 0.12 }} /></div><small>{bytes(device.bytes)} transferred</small></div>)}</div> : <Empty icon={Network} title="Waiting for devices">Processed source addresses will appear here.</Empty>}<div className="panel-bottom"><Info size={12} /> {monitorMode ? 'Visibility is limited to this laptop’s selected interface, not the entire router network.' : d?.mode === 'lab' ? 'Source addresses include authorized lab observations and any synthetic replay.' : 'Documentation addresses are used in demo traffic.'}</div></section></div>
    <section className="panel recent-traffic-panel"><SectionHeader title={monitorMode ? "Recent observed flows" : "Recent connections"} subtitle={monitorMode ? "Actual metadata received from the local collector" : "The latest records processed by Sentinel"} action={<button className="text-button" onClick={() => navigate('traffic')}>Open traffic explorer <ArrowRight size={13} /></button>} /><ConnectionTable monitorMode={monitorMode} records={d?.recent_connections.slice(0, 5) ?? []} compactView /></section>
  </>
}

function ConnectionTable({ records, compactView = false, monitorMode = false }: { records: Connection[]; compactView?: boolean; monitorMode?: boolean }) {
  if (!records.length) return <Empty icon={Cable} title={monitorMode ? "No observed flow records found" : "No connections found"}>{monitorMode ? "Wait for actual collector metadata or adjust your filters. No synthetic replay is used in monitoring mode." : "Start the replay or adjust your filters to explore connection records."}</Empty>
  const scoreDescription = monitorMode ? 'Historical benchmark outlier score: informational only, not validated for live metadata and not an attack probability' : 'Uncalibrated outlier score, not attack probability'
  return <div className="table-scroll"><table className="data-table">
    <thead><tr><th>TIMESTAMP</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>ORIGIN</th>{!compactView && <th>DURATION</th>}<th>{compactView ? 'TRANSFERRED' : 'SENT / RECEIVED'}</th>{!compactView && <th title={scoreDescription}>{monitorMode ? "BASELINE SCORE" : "ML SCORE"}</th>}<th>STATE</th><th>DETECTION</th></tr></thead>
    <tbody>{records.map(r => <tr key={r.id}>
      <td className="cell-time"><time dateTime={r.timestamp} title={r.timestamp}>{time(r.timestamp)}</time></td>
      <td><code>{r.src_ip}</code><span className="port">:{r.src_port}</span></td>
      <td><code>{r.dst_ip}</code><span className="port">:{r.dst_port}</span></td>
      <td><span className="protocol-chip">{r.protocol.toUpperCase()}</span>{r.service && r.service !== '-' && <small className="service-label">{r.service}</small>}</td>
      <td><OriginBadge value={r.origin} collector={r.provenance?.collector} /></td>
      {!compactView && <td className="cell-muted" title={r.origin === 'live' ? 'Observed time span inside a bounded window; the complete session may be longer.' : undefined}>{r.provenance?.duration_is_lower_bound ? '≥' : ''}{Number(r.duration).toFixed(2)}s</td>}
      <td>{compactView ? <span>{bytes(r.bytes_sent + r.bytes_received)}</span> : <div className="directional-bytes"><span><i>↑ sent</i>{bytes(r.bytes_sent)}</span><span><i>↓ received</i>{bytes(r.bytes_received)}</span></div>}</td>
      {!compactView && <td><span className="model-score" title={scoreDescription}>{baselineScore(r) !== null ? baselineScore(r)!.toFixed(3) : '—'}</span>{r.origin === 'live' && <small className="score-qualification">Informational only</small>}</td>}
      <td><span className="connection-state" title={r.origin === 'live' ? 'Observed transport flags or window state; not an authentication result.' : undefined}>{r.status}</span></td>
      <td><span className={`detection-result ${r.is_anomaly ? 'anomaly' : ''}`} title={r.origin === 'live' ? 'Saved findings may include historical baseline alerts. No finding is not proof of benign behavior.' : undefined}><span />{findingLabel(r, monitorMode)}</span></td>
    </tr>)}</tbody>
  </table></div>
}

function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) { return <label className="search-input"><Search size={16} /><input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder} />{value && <button aria-label="Clear search" onClick={() => onChange('')}><X size={13} /></button>}</label> }
function exportConnections(records: Connection[]) {
  const content = connectionCsv(records)
  const url = URL.createObjectURL(new Blob([content], { type: 'text/csv;charset=utf-8' }))
  const link = document.createElement('a'); link.href = url; link.download = 'sentinel-connection-records.csv'; link.click(); URL.revokeObjectURL(url)
}
function TrafficPage({ records, total, search, setSearch, protocol, setProtocol, offset, setOffset, monitorMode = false, loading = false, loadError = '' }: { monitorMode?: boolean; loading?: boolean; loadError?: string; records: Connection[]; total: number; search: string; setSearch: (s: string) => void; protocol: string; setProtocol: (s: string) => void; offset: number; setOffset: (n: number) => void }) {
  return <section className="panel" aria-busy={loading}><SectionHeader title={monitorMode ? "Observed flow records" : "Network connection records"} subtitle={monitorMode ? "Selected laptop Ethernet interface · bounded-window metadata" : "Search addresses and inspect observed connection metadata"} action={<button className="button button-secondary button-small" disabled={loading || !!loadError || !records.length} onClick={() => exportConnections(records)}><Download size={14} />Export this page</button>} /><div className="filter-toolbar"><SearchBox value={search} onChange={setSearch} placeholder="Search IP address, service, or state…" /><div className="select-filter"><Filter size={14} /><select aria-label="Filter protocol" value={protocol} onChange={e => setProtocol(e.target.value)}><option value="">All protocols</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></div><span className="filter-count">{loading ? 'Loading matching records…' : loadError ? 'Records unavailable' : `${num(total)} ${monitorMode ? 'flow records' : 'connections'}`}</span></div>{loading ? <div className="loading-state" role="status"><LoaderCircle className="spin" size={22} /><p>Loading matching records…</p></div> : loadError ? <Empty title="Records could not be loaded">Use Retry above to reload the current filters.</Empty> : <ConnectionTable monitorMode={monitorMode} records={records} />}<div className="pagination"><span>{loading ? 'Updating results…' : loadError ? 'Results unavailable' : total ? `${num(offset + 1)}–${num(Math.min(offset + records.length, total))} of ${num(total)} records` : '0 records'}</span><div><button className="button button-subtle button-small" disabled={loading || !!loadError || offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}><ChevronLeft size={14} />Previous</button><button className="button button-subtle button-small" disabled={loading || !!loadError || offset + 50 >= total} onClick={() => setOffset(offset + 50)}>Next<ChevronRight size={14} /></button></div></div></section>
}

function IncidentsPage({ records, total, search, setSearch, severity, setSeverity, status, setStatus, source, setSource, openIncident, monitorMode = false, loading = false, loadError = '' }: { monitorMode?: boolean; loading?: boolean; loadError?: string; records: Incident[]; total: number; search: string; setSearch: (s: string) => void; severity: string; setSeverity: (s: string) => void; status: string; setStatus: (s: string) => void; source: string; setSource: (s: string) => void; openIncident: (id: string | number) => void }) {
  return <><div className="incident-guidance"><div><BookOpen size={17} /><strong>Every alert has a story.</strong><span>Open an incident to inspect its evidence, track its status, and add investigation notes.</span></div><Badge>{loading ? 'Loading incidents…' : loadError ? 'Incidents unavailable' : `${num(total)} matching incidents`}</Badge></div><section className="panel" aria-busy={loading}><div className="filter-toolbar incident-filters"><SearchBox value={search} onChange={setSearch} placeholder="Search incidents or IP addresses…" /><select aria-label="Filter severity" value={severity} onChange={e => setSeverity(e.target.value)}><option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}</select><select aria-label="Filter status" value={status} onChange={e => setStatus(e.target.value)}><option value="">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select><select aria-label="Filter detection source" value={source} onChange={e => setSource(e.target.value)}><option value="">All sources</option><option value="rule">Detection rules</option><option value="ml">{monitorMode ? "Historical baseline ML" : "AI anomalies"}</option></select>{(search || severity || status || source) && <button className="text-button" onClick={() => { setSearch(''); setSeverity(''); setStatus(''); setSource('') }}>Clear filters</button>}</div>{loading ? <div className="loading-state" role="status"><LoaderCircle className="spin" size={22} /><p>Loading matching incidents…</p></div> : loadError ? <Empty title="Incidents could not be loaded">Use Retry above to reload the current filters.</Empty> : records.length ? <div className="table-scroll"><table className="data-table incident-table"><thead><tr><th>INCIDENT</th><th>{monitorMode ? "SAVED PRIORITY" : "SEVERITY"}</th><th>SOURCE ADDRESS</th><th>DETECTION SOURCE</th><th>ORIGIN</th><th>STATUS</th><th>LAST SEEN</th><th /></tr></thead><tbody>{records.map(i => <tr key={i.id} onClick={() => openIncident(i.id)} className="clickable-row"><td><button className="incident-title-button" onClick={() => openIncident(i.id)}><strong>{i.title}</strong><small>{incidentRef(i.id)} <span>·</span> {num(i.count)} correlated events</small></button></td><td><Badge tone={i.severity} dot>{i.severity}</Badge></td><td><code>{i.src_ip}</code></td><td><Source value={i.detection_source} origin={i.origin} /></td><td><OriginBadge value={i.origin} collector={i.connection?.provenance?.collector} genericLab /></td><td><Badge tone={i.status}>{i.status}</Badge></td><td className="cell-time"><time dateTime={i.last_seen || i.timestamp} title={i.last_seen || i.timestamp}>{date(i.last_seen || i.timestamp)}</time></td><td><ChevronRight size={15} /></td></tr>)}</tbody></table></div> : <Empty icon={ShieldAlert} title="No matching incidents">{monitorMode ? "Try changing your filters. Any findings must come from actual received metadata; no simulated incidents are generated here." : "Try changing your filters, or run a simulation to generate detection findings."}</Empty>}<div className="panel-bottom"><Info size={13} /> Correlated alerts group related events. Rules and model detections remain independently identifiable.</div></section></>
}

function ModelPage({ model, monitorMode = false }: { model: ModelInfo; monitorMode?: boolean }) {
  const metrics = asRecord(model.metrics ?? asRecord(model.evaluation).metrics ?? model.evaluation)
  const dataset = asRecord(model.dataset)
  const split = asRecord(model.split ?? model.splits)
  const loaded = Boolean(model.ready ?? model.loaded ?? model.model_loaded ?? model.available ?? Object.keys(metrics).length)
  const matrix = (metrics.confusion_matrix ?? model.confusion_matrix) as number[][] | undefined
  const featureNames = (model.feature_names ?? model.features ?? []) as unknown[]
  const metricItems = [{ title: 'Precision', key: 'precision', alt: 'precision_score', detail: 'How often flagged test events were attacks' }, { title: 'Recall', key: 'recall', alt: 'recall_score', detail: 'Share of test attacks detected' }, { title: 'F1 score', key: 'f1', alt: 'f1_score', detail: 'Balance of precision and recall' }, { title: 'False-positive rate', key: 'false_positive_rate', alt: 'fpr', detail: 'Benign test records flagged as anomalous' }]
  return <><section className="panel model-summary"><div className="model-summary-icon"><BrainCircuit size={30} strokeWidth={1.4} /></div><div><div className="eyebrow">{monitorMode ? "HISTORICAL BENCHMARK BASELINE" : "ANOMALY DETECTION ENGINE"}</div><h2>{display(model.name ?? model.model_type ?? model.algorithm ?? 'Isolation Forest')}</h2><p>{monitorMode ? "Loaded baseline scores are informational; live findings use context-aware rules." : "Unsupervised anomaly detection with per-event indicators to support analyst review."}</p></div><Badge tone={loaded ? 'green' : 'amber'} dot>{loaded ? monitorMode ? 'Baseline available' : 'Model available' : 'Rule-only fallback'}</Badge></section><div className="model-note"><Info size={17} /><p><strong>{monitorMode ? "Benchmark evaluation is separate from laptop observations." : "Evaluation is separate from the demo."}</strong> {monitorMode ? "The values below come from the saved historical dataset evaluation. Live metadata compatibility is unvalidated, so these baseline scores do not create new live ML incidents. Existing historical incidents remain unchanged." : "The synthetic replay demonstrates the application. Any metrics below come from the saved evaluation report, and do not establish performance on your network."}</p></div><div className="stats-grid model-metrics">{metricItems.map(m => <article className="stat-card" key={m.key}><div className="stat-top"><span>{m.title}</span><Activity size={15} /></div><div className="stat-value">{numeric(metrics[m.key] ?? metrics[m.alt]) !== undefined ? percentage(numeric(metrics[m.key] ?? metrics[m.alt])) : '—'}</div><p>{m.detail}</p></article>)}</div><div className="model-grid"><section className="panel"><SectionHeader title="Model provenance" subtitle="Reproducibility and data lineage" /><dl className="detail-list"><div><dt>Dataset</dt><dd>{display(typeof model.dataset === 'string' ? model.dataset : dataset.name ?? model.dataset_name)}</dd></div><div><dt>Model trained</dt><dd>{display(model.trained_at ?? model.training_timestamp)}</dd></div><div><dt>Training records</dt><dd>{display(model.train_samples ?? model.training_samples ?? asRecord(model.counts).train_benign_used ?? split.train ?? split.training)}</dd></div><div><dt>Evaluation records</dt><dd>{display(model.test_samples ?? model.evaluation_samples ?? asRecord(model.counts).test ?? split.test)}</dd></div><div><dt>Decision threshold</dt><dd>{display(model.threshold ?? model.decision_threshold)}</dd></div><div><dt>Dataset fingerprint</dt><dd><code className="wrap-code">{display(dataset.sha256 ?? model.dataset_sha256 ?? model.data_sha256 ?? model.sha256)}</code></dd></div></dl>{typeof (dataset.url ?? model.dataset_url ?? model.citation_url ?? model.source_url) === 'string' && <a className="external-text-link" href={String(dataset.url ?? model.dataset_url ?? model.citation_url ?? model.source_url)} target="_blank" rel="noreferrer">View dataset source <ExternalLink size={13} /></a>}</section><section className="panel"><SectionHeader title="Held-out evaluation" subtitle="Confusion matrix · actual labels × predictions" />{matrix && matrix.length === 2 && matrix.every(r => Array.isArray(r) && r.length === 2) ? <div className="confusion-matrix"><div /><span>Predicted benign</span><span>Predicted attack</span><span>Actual benign</span><div className="matrix-cell correct"><strong>{num(matrix[0][0])}</strong><small>True negative</small></div><div className="matrix-cell"><strong>{num(matrix[0][1])}</strong><small>False positive</small></div><span>Actual attack</span><div className="matrix-cell"><strong>{num(matrix[1][0])}</strong><small>False negative</small></div><div className="matrix-cell correct"><strong>{num(matrix[1][1])}</strong><small>True positive</small></div></div> : <Empty icon={Activity} title="Evaluation not available">Run the training pipeline to produce an evaluation report with labeled, held-out data.</Empty>}</section></div><div className="model-grid"><section className="panel"><SectionHeader title="Traffic features" subtitle="The inputs used by the anomaly detector" />{featureNames.length ? <div className="feature-tags">{featureNames.map((f, i) => <span key={i}><Cpu size={13} />{display(typeof f === 'object' ? asRecord(f).name : f).replace(/_/g, ' ')}</span>)}</div> : <div className="panel-text">Feature names will appear when model metadata is available.</div>}<div className="panel-bottom"><Shield size={12} /> IP addresses are context for investigation, not proof of malicious behavior.</div></section><section className="panel limitation-panel"><SectionHeader title="Interpret with care" subtitle="Anomaly does not necessarily mean attack" /><ul><li>Rare legitimate traffic can trigger false positives.</li><li>Dataset results do not transfer automatically to a different network.</li><li>Review connection context and supporting rules before escalating.</li><li>{monitorMode ? "Observed anomalies require investigation and are not proof of an attack or an authentication failure." : "Replay indicators are explicitly simulated and are not live network findings."}</li>{Array.isArray(model.limitations) && model.limitations.map((item, index) => <li key={index}>{display(item)}</li>)}</ul>{typeof model.limitations === 'string' && <p className="panel-text">{model.limitations}</p>}</section></div></>
}

function MonitoringPanel({ info }: { info?: MonitoringInfo }) {
  const status = monitoringStatusText(info?.status)
  return <section className="panel monitoring-panel">
    <SectionHeader title="Local observation provenance" subtitle="Actual metadata, not a synthetic replay or file-import label" action={<Badge tone={info?.status === 'receiving' ? 'green' : info?.status === 'stale' ? 'amber' : 'neutral'}>{status}</Badge>} />
    <dl className="detail-list">
      <div><dt>Server configuration</dt><dd>{info ? info.enabled ? 'Local metadata ingestion enabled' : 'Monitoring disabled' : 'Not reported'}</dd></div>
      <div><dt>Collector</dt><dd>{info?.collector ?? 'Not reported'}</dd></div>
      <div><dt>Selected interface</dt><dd>{info?.interface_label ?? 'Not reported'}</dd></div>
      <div><dt>Last metadata ingest</dt><dd>{info?.last_ingest_at ? date(info.last_ingest_at) : 'No metadata received'}</dd></div>
      <div><dt>Ingested flow records</dt><dd>{info ? num(info.ingested_records) : 'Not reported'}</dd></div>
      <div><dt>Retained flow records</dt><dd>{info ? num(info.retained_records) : 'Not reported'}</dd></div>
      <div><dt>Retention row limit</dt><dd>{info ? num(info.max_rows) : 'Not reported'}</dd></div>
      <div><dt>Observation scope</dt><dd>{info?.observation_scope === 'selected_interface_passive' ? 'Selected local interface only' : info?.observation_scope ?? 'Not reported'}</dd></div>
      <div><dt>Byte measurements</dt><dd>{info?.measurement_semantics === 'transport_payload_bytes' ? 'Header-derived transport payload lengths within collection windows' : info?.measurement_semantics ?? 'Not reported'}</dd></div>
    </dl>
    <div className="monitoring-limitations"><h3>Collection boundaries</h3><ul>
      <li>Collection starts explicitly from the local CLI and delivers a batch after its bounded observation window stops.</li>
      <li>Recent API ingestion does not prove that a collector is currently running.</li>
      <li>Records can cover only part of a session. Local interface visibility does not cover every device behind the router.</li>
      <li>Observed transport states are not login results. Metadata alone cannot establish password failures or an attack.</li>
      {(info?.limitations ?? []).map((limitation, index) => <li key={index}>{limitation}</li>)}
    </ul></div>
    <div className="panel-bottom"><Shield size={12} /> Private local metadata. No capture controls are available in this dashboard.</div>
  </section>
}

function SystemPage({ system, onIngest }: { system: SystemInfo; onIngest: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [message, setMessage] = useState('')
  const [uploadError, setUploadError] = useState('')
  const [ingestionKey, setIngestionKey] = useState('')
  const isLab = system.mode === 'lab' || system.mode === 'local' || system.lab_mode === true
  const monitorMode = system.mode === 'monitor'
  const upload = async () => {
    if (!file) return
    if (file.size > 1_500_000) { setUploadError('Choose a Zeek log smaller than 1.5 MB. The server also limits each import to 10,000 records.'); return }
    setUploading(true); setMessage(''); setUploadError('')
    try {
      const content = await file.text()
      const firstRecord = content.split(/\r?\n/).find(line => line.trim() && !line.startsWith('#'))
      const result = await api<Record<string, unknown>>('/ingest/zeek', { method: 'POST', headers: ingestionKey ? { 'X-Sentinel-Key': ingestionKey } : {}, body: JSON.stringify({ content, format: firstRecord?.trim().startsWith('{') ? 'json' : 'tsv' }) })
      setMessage(`Log processed. ${display(result.ingested ?? result.processed ?? result.count ?? result.accepted ?? 'See traffic explorer for')} records.`); setFile(null); onIngest()
    }
    catch (err) { setUploadError(err instanceof Error ? err.message : 'Log ingestion failed.') }
    finally { setUploading(false) }
  }
  const uptime = numeric(system.uptime_seconds)
  return <><div className="system-status-strip"><div className="system-status-symbol"><CircleCheck size={23} /></div><div><h2>{monitorMode ? "Observed Ethernet metadata" : "Local application environment"}</h2><p>{monitorMode ? "Bounded local collection is started explicitly from the CLI. The dashboard reports received metadata." : "Service status is reported by the backend. Privileged capture is disabled by default."}</p></div><Badge tone={monitorMode ? 'green' : isLab ? 'amber' : 'cyan'} dot>{monitorMode ? 'Local laptop monitoring' : isLab ? 'Authorized lab mode' : 'Safe demonstration'}</Badge></div><div className="system-cards"><article className="panel system-card"><div className="system-card-icon"><Server size={20} /></div><h3>FastAPI backend</h3><Badge tone={Object.keys(system).length ? 'green' : 'neutral'} dot>{Object.keys(system).length ? 'Responding' : 'Waiting'}</Badge><p>Uptime {uptime !== undefined ? `${Math.floor(uptime / 3600)}h ${Math.floor(uptime % 3600 / 60)}m ${Math.floor(uptime % 60)}s` : 'not available'}</p></article><article className="panel system-card"><div className="system-card-icon"><Database size={20} /></div><h3>SQLite persistence</h3><Badge tone={system.database ? 'green' : 'neutral'} dot>{system.database ? 'Configured' : 'Waiting'}</Badge><p>Connection records, incidents, and investigation history.</p></article><article className="panel system-card"><div className="system-card-icon"><BrainCircuit size={20} /></div><h3>Detection engine</h3><Badge tone={monitorMode ? 'cyan' : system.model_loaded ? 'green' : 'amber'} dot>{monitorMode ? 'Rules for live findings' : system.model_loaded ? 'Rules + AI model' : 'Rule-based detection'}</Badge><p>{monitorMode ? system.model_loaded ? 'Baseline score informational; no validated live ML detector is installed.' : 'Rule findings available; the historical baseline artifact is unavailable.' : system.model_loaded ? 'Model artifact loaded for local inference.' : 'Train and install a model to enable AI inference.'}</p></article></div><div className="model-grid"><section className="panel"><SectionHeader title="Runtime configuration" subtitle="Reported by the connected API" /><dl className="detail-list">{Object.entries(system).filter(([key]) => !['services', 'uptime_seconds', 'monitoring'].includes(key)).map(([key, value]) => <div key={key}><dt>{key.replace(/_/g, ' ')}</dt><dd>{display(value)}</dd></div>)}</dl>{!Object.keys(system).length && <Empty icon={Server} title="Waiting for runtime information">The application will report its configuration when the backend is connected.</Empty>}</section>{monitorMode ? <MonitoringPanel info={system.monitoring} /> : <section className="panel lab-ingest-panel"><SectionHeader title="Authorized lab ingestion" subtitle="Read existing Zeek connection logs" action={<Badge tone={isLab ? 'green' : 'neutral'}>{isLab ? 'Enabled' : 'Disabled in demo'}</Badge>} /><div className="ingest-description"><Upload size={26} strokeWidth={1.3} /><p>Import a Zeek <code>conn.log</code> in TSV or JSON format. Log ingestion reads existing records and never initiates network connections.</p><label className={`file-drop ${!isLab ? 'disabled' : ''}`}><FileText size={18} /><span>{file?.name ?? 'Choose a Zeek log file'}</span><input type="file" accept=".log,.json,.jsonl,.tsv,.txt" disabled={!isLab || uploading} onChange={e => { setFile(e.target.files?.[0] ?? null); setMessage(''); setUploadError('') }} /></label><label className="ingestion-key"><span>Ingestion key <small>if configured on the backend</small></span><input type="password" autoComplete="off" aria-label="Ingestion API key" value={ingestionKey} disabled={!isLab || uploading} onChange={e => setIngestionKey(e.target.value)} placeholder="Optional · kept only in this page" /></label><button className="button button-secondary" disabled={!isLab || !file || uploading} onClick={() => void upload()}>{uploading ? <LoaderCircle size={14} className="spin" /> : <Upload size={14} />}Process log</button>{message && <p role="status" className="success-text">{message}</p>}{uploadError && <p role="alert" className="error-text">{uploadError}</p>}{!isLab && <small>Start the backend with authorized lab mode enabled to use ingestion. See <code>docs/lab-setup.md</code> for setup and permissions.</small>}</div></section>}</div><section className="panel security-boundaries"><SectionHeader title="Designed with clear boundaries" subtitle="Passive observation and analyst-led investigation" /><div><span><Check size={16} />{monitorMode ? "Selected local interface" : "Synthetic, isolated demonstration"}</span><span><Check size={16} />{monitorMode ? "Metadata-only records" : "Passive log ingestion"}</span><span><Check size={16} />No active scanning</span><span><Check size={16} />No automatic blocking</span></div></section></>
}

function trapFocus(event: React.KeyboardEvent, root: HTMLElement | null) {
  if (event.key !== 'Tab') return
  const focusable = root?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href]')
  if (!focusable?.length) { event.preventDefault(); return }
  const first = focusable[0], last = focusable[focusable.length - 1]
  if (event.shiftKey && (document.activeElement === first || document.activeElement === root)) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && (document.activeElement === last || document.activeElement === root)) { event.preventDefault(); first.focus() }
}

function Modal({ close, title, children, drawer = false }: { close: () => void; title: string; children: ReactNode; drawer?: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const original = document.activeElement as HTMLElement | null
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    ref.current?.focus()
    return () => { document.body.style.overflow = overflow; original?.focus() }
  }, [])
  const onKey = (event: React.KeyboardEvent) => {
    if (event.key === 'Escape') close()
    trapFocus(event, ref.current)
  }
  return <div className={`modal-backdrop ${drawer ? 'drawer-backdrop' : ''}`} onMouseDown={e => { if (e.target === e.currentTarget) close() }}><div className={drawer ? 'incident-drawer' : 'dialog'} role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref} onKeyDown={onKey}><button className="icon-button modal-close" onClick={close} aria-label="Close dialog"><X size={20} /></button>{children}</div></div>
}

function EvidenceList({ items, empty }: { items: string[]; empty: string }) {
  return items.length ? <ul className="indicator-list">{items.map((item, index) => <li key={index}><span />{item}</li>)}</ul> : <p className="section-description">{empty}</p>
}

function LiveCompatibilityReview({ analysis }: { analysis?: Incident['analysis'] }) {
  const assessment = analysis?.model_assessment
  return <>
    <div className="compatibility-notice" role="note"><Info size={16} /><div><strong>Current read-only compatibility review</strong><p>{analysis?.notice ?? 'A current compatibility assessment was not supplied. The saved incident remains unchanged.'}</p><small>Saved priority, status, indicators and investigation history are not rewritten by this view.</small></div></div>
    <section className="drawer-section">
      <h3><BrainCircuit size={15} />Historical baseline comparison</h3>
      <p className="section-description">This benchmark model is not validated for live Ethernet metadata. An outlier score is not an attack probability.</p>
      <div className="baseline-values"><div><span>Saved baseline score</span><strong>{modelNumber(assessment?.score)}</strong><small>{scoreSourceText(assessment)}</small></div><div><span>{assessment?.threshold_source === 'stored_at_ingest' ? 'Saved comparison threshold' : 'Reference comparison threshold'}</span><strong>{modelNumber(assessment?.threshold)}</strong><small>{thresholdSourceText(assessment)}</small></div></div>
      <dl className="drawer-details"><div><dt>Model</dt><dd>{assessment?.name ?? 'Not reported'}</dd></div><div><dt>Model version</dt><dd>{assessment?.model_version ?? 'Not reported'}</dd></div><div><dt>Score comparison</dt><dd>{assessment?.above_threshold === true ? 'Above comparison threshold' : assessment?.above_threshold === false ? 'At or below comparison threshold' : 'Not available'}</dd></div><div><dt>Live alert eligibility</dt><dd>{assessment?.alert_eligible === false ? 'Informational score only' : 'Not reported'}</dd></div></dl>
      <p className="assessment-caveat">Exceeding this reference threshold does not establish suspiciousness in the live collection domain. Feature-range and category indicators are heuristic explanations, not causal score attribution.</p>
      <h4 className="evidence-subheading">Compatibility limitations</h4>
      <EvidenceList items={assessment?.reasons ?? []} empty="No additional compatibility reasons were supplied." />
    </section>
  </>
}

function ObservationContext({ analysis }: { analysis?: Incident['analysis'] }) {
  const context = analysis?.protocol_context
  return <>
    <section className="drawer-section"><h3><Cable size={15} />Protocol and local-network context</h3>
      <div className="protocol-context"><strong>{context?.label ?? 'Context not available'}</strong><p>{context?.basis ?? 'No protocol context was supplied for this anchor observation.'}</p></div>
      <EvidenceList items={context?.notes ?? []} empty="No additional protocol context was supplied." />
      <p className="assessment-caveat">A port or address pattern does not verify the application or prove benign behavior. Familiar protocols can still carry unusual activity.</p>
    </section>
    <section className="drawer-section"><h3><Info size={15} />Collection limitations</h3><EvidenceList items={analysis?.observation_limits ?? []} empty="Collection limitations were not supplied for this observation." /></section>
    <section className="drawer-section"><h3><BookOpen size={15} />Additional evidence to review</h3><p className="section-description">These are missing evidence or investigation suggestions; this page does not collect them.</p><EvidenceList items={analysis?.additional_evidence ?? []} empty="No additional evidence suggestions were supplied." /></section>
  </>
}

function IncidentDrawer({ id, close, onUpdate, readOnly = false }: { id: string | number; close: () => void; onUpdate: () => void; readOnly?: boolean }) {
  const [incident, setIncident] = useState<Incident | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    let active = true
    const abort = new AbortController()
    setIncident(null); setError(''); setNote(''); setLoading(true)
    api<Incident>(`/incidents/${encodeURIComponent(id)}`, { signal: abort.signal })
      .then(value => { if (active) setIncident(value) })
      .catch(err => { if (active) setError(err instanceof Error ? err.message : 'Incident evidence could not be loaded.') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false; abort.abort() }
  }, [id, retry])
  const save = async (body: { status?: string; note?: string }) => {
    if (readOnly) return
    setBusy(true); setError('')
    try {
      const detail = await api<Incident>(`/incidents/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) })
      setIncident(detail); if (body.note) setNote(''); onUpdate()
    }
    catch (err) { setError(err instanceof Error ? err.message : 'Unable to update the incident.') }
    finally { setBusy(false) }
  }
  const history = incident?.history ?? (Array.isArray(incident?.notes) ? incident.notes : [])
  const live = incident?.origin === 'live'
  const observation = incident?.connection
  const controlled = observation?.provenance?.collector === 'localhost-lab'
  const heuristic = incident?.detection_source === 'ml'
  return <Modal close={close} drawer title={`Investigate incident ${id}`}>
    <div className="drawer-header"><div className="eyebrow"><ShieldAlert size={13} />INCIDENT INVESTIGATION</div><div className="incident-number">{incidentRef(id)}</div></div>
    {error && <div role="alert" className="drawer-error"><span>{error}</span>{!incident && <button className="button button-subtle button-small" onClick={() => setRetry(value => value + 1)}>Retry <RefreshCw size={13} /></button>}</div>}
    {loading ? <div className="loading-state" role="status"><LoaderCircle className="spin" size={24} /><p>Loading incident evidence…</p></div> : !incident ? <Empty icon={ShieldAlert} title="Incident evidence unavailable">Retry the request or close this investigation.</Empty> : <>
      <div className="drawer-title"><div className="incident-badges"><Badge tone={incident.severity} dot>{incident.severity} {live ? 'saved priority' : 'severity'}</Badge><OriginBadge value={incident.origin} collector={observation?.provenance?.collector} genericLab />{incident.analysis?.historical_alert && <Badge>Historical saved alert</Badge>}</div><h2>{incident.title}</h2><p>{incident.description}</p><Source value={incident.detection_source} origin={incident.origin} />{live && <p className="priority-caveat">Saved triage priority is not confidence that an attack occurred.</p>}{readOnly && <p className="priority-caveat">Read-only demonstration. Investigation status and notes cannot be changed.</p>}</div>
      <div className="incident-status-control"><span>Investigation status</span><select aria-label="Investigation status" value={incident.status} disabled={busy || readOnly} onChange={e => void save({ status: e.target.value })}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select></div>
      <section className="drawer-section"><h3><Network size={15} />{live ? 'Observed flow context' : 'Connection context'}</h3><div className="connection-route"><div><span>SOURCE ADDRESS</span><code>{incident.src_ip}</code></div><ArrowRight size={19} /><div><span>DESTINATION ADDRESS</span><code>{incident.dst_ip}</code></div></div>
        {observation && <><p className="section-description">Linked anchor observation; correlated events may include additional flows.</p><dl className="drawer-details observation-details"><div><dt>Protocol</dt><dd>{observation.protocol.toUpperCase()}</dd></div><div><dt>Source / destination port</dt><dd><code>{observation.src_port} → {observation.dst_port}</code></dd></div><div><dt>Observed state</dt><dd><code>{observation.status}</code></dd></div><div><dt>Reported service</dt><dd>{observation.service || 'Not reported'}</dd></div><div><dt>Observed duration</dt><dd>{observation.provenance?.duration_is_lower_bound ? '≥ ' : ''}{Number(observation.duration).toFixed(3)} seconds</dd></div><div><dt>Sent / received bytes</dt><dd>{num(observation.bytes_sent)} / {num(observation.bytes_received)}</dd></div>{live && <><div><dt>Observed local role</dt><dd>{observation.provenance?.local_role ?? 'Not reported'}</dd></div><div><dt>Window end</dt><dd>{date(observation.provenance?.window_end)}</dd></div></>}</dl></>}
        {observation?.provenance && <dl className="drawer-details observation-details"><div><dt>Evidence collector</dt><dd>{observation.provenance.collector ?? 'Not reported'}</dd></div><div><dt>Measurement basis</dt><dd>{observation.provenance.measurement_semantics === 'application_bytes' ? 'Application bytes recorded by the owned local endpoints' : observation.provenance.measurement_semantics === 'transport_payload_bytes' ? 'Header-derived transport payload lengths, including retransmissions' : observation.provenance.measurement_semantics ?? 'Not reported'}</dd></div><div><dt>Observation scope</dt><dd>{observation.provenance.observation_scope === 'owned_loopback_services' ? 'Disposable owned localhost services' : observation.provenance.observation_scope === 'selected_interface_passive' ? 'Selected local Ethernet interface' : observation.provenance.observation_scope ?? 'Not reported'}</dd></div><div><dt>Collection ID</dt><dd><code>{observation.provenance.collection_id ?? 'Not reported'}</code></dd></div><div><dt>Anchor flow ID</dt><dd><code>{observation.provenance.flow_id ?? 'Not reported'}</code></dd></div></dl>}
        <dl className="drawer-details"><div><dt>First observed</dt><dd><time dateTime={incident.timestamp} title={incident.timestamp}>{date(incident.timestamp)}</time></dd></div><div><dt>Last observed</dt><dd><time dateTime={incident.last_seen} title={incident.last_seen}>{date(incident.last_seen)}</time></dd></div><div><dt>Correlated events</dt><dd>{num(incident.count)}</dd></div><div><dt>Detection reference</dt><dd><code>{incident.rule_id || 'isolation_forest'}</code></dd></div><div><dt>Connection reference</dt><dd><code>CONN-{incident.connection_id}</code></dd></div></dl>
        {!observation && live && <p className="assessment-caveat">The linked observation is unavailable. Protocol, ports and original measurements are not inferred from the incident addresses.</p>}
      </section>
      {live && <LiveCompatibilityReview analysis={incident.analysis} />}
      <section className="drawer-section"><h3><Radar size={15} />{heuristic ? 'Saved model indicators' : 'Rule trigger evidence'}</h3><p className="section-description">{heuristic ? 'These saved training-range/category indicators are explanatory heuristics, not causal feature attribution or evidence of malicious intent.' : 'Conditions recorded by the rule. Review the relevant observations, thresholds and collection limitations before attributing intent.'}</p><EvidenceList items={incident.indicators ?? []} empty="No additional indicators were stored for this incident." /></section>
      {(live || controlled) && <ObservationContext analysis={incident.analysis} />}
      <section className="drawer-section"><h3><FileText size={15} />Investigation notes</h3><form onSubmit={e => { e.preventDefault(); if (note.trim()) void save({ note: note.trim() }) }}><textarea aria-label="Investigation note" placeholder={readOnly ? "Notes are read-only in this demonstration." : "Record your findings, context, or next steps…"} maxLength={4000} value={note} disabled={readOnly} onChange={e => setNote(e.target.value)} rows={4} /><div className="note-actions"><span>{readOnly ? 'Read-only demonstration' : 'Saved to incident history'}</span><button className="button button-primary button-small" disabled={readOnly || !note.trim() || busy} type="submit">{busy ? <LoaderCircle size={13} className="spin" /> : <Send size={13} />}Add note</button></div></form></section>
      <section className="drawer-section"><h3><Clock3 size={15} />Incident history</h3>{history.length ? <ol className="history-list">{[...history].reverse().map((h, i) => <li key={h.id ?? i}><span className="history-dot" /><div><strong>{historyTitle(h.action)}</strong>{(h.note || h.details) && <p>{h.note || h.details}</p>}<time>{date(h.timestamp)}</time></div></li>)}</ol> : <p className="section-description">Updates and notes will appear here as your investigation progresses.</p>}</section>
      <div className="drawer-safe-note">{incident.origin === 'live' ? <Cable size={15} /> : incident.origin === 'lab' ? <Upload size={15} /> : <FlaskConical size={15} />}<span>{originPresentation(incident.origin, observation?.provenance?.collector).description}</span></div>
    </>}
  </Modal>
}

export default App
