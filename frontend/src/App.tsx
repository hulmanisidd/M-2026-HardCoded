import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  Background, BackgroundVariant, Controls, MarkerType, MiniMap, ReactFlow,
  type Edge, type Node,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { X } from 'lucide-react'
import { getGraph, getHealth, getOverlays, getPaths, getPipeline, getScenarios, simulateRemediation } from './api'
import { layout } from './layout'
import { edgeTypes, nodeTypes, styleOf, TYPE_STYLE, type CircleData } from './graphParts'
import type {
  GraphEdge, GraphNode, GraphResponse, OverlaysResponse, HealthResponse, PathsResponse, PipelineResponse, ScenarioSummary, SimulationResponse,
} from './types'

const LAYER = {
  attack: { label: 'Attack paths', color: '#ef4444' },
  fix: { label: 'Fixes', color: '#a855f7' },
  backup: { label: 'Backup routes', color: '#10b981' },
} as const
type LayerKey = keyof typeof LAYER
type Item = { layer: LayerKey; id: string; title: string; status: string; note: string; edge_ids: string[] }
type Focus = { layer: LayerKey; id: string } | null
type Sel = { kind: 'node' | 'edge'; id: string } | null
type Load = 'loading' | 'ready' | 'error'

const card = 'glass rise rounded-3xl'
const TONES = {
  slate: 'bg-slate-900/5 text-slate-600', red: 'bg-rose-500/10 text-rose-700',
  amber: 'bg-amber-500/15 text-amber-800', green: 'bg-emerald-500/12 text-emerald-700',
  purple: 'bg-purple-500/10 text-purple-700', blue: 'bg-sky-500/10 text-sky-700',
}
type Tone = keyof typeof TONES

const pretty = (s: string) => s.replace(/_/g, ' ')
const feasTone = (s: string): Tone => (s === 'feasible_under_model' ? 'red' : s === 'conditional' ? 'amber' : 'slate')
const statusTone = (s: string): Tone =>
  s === 'confirmed' ? 'green' : s === 'inferred' ? 'blue' : s === 'invalidated' ? 'red' : 'amber'
const STATUS_HELP: Record<string, string> = {
  confirmed: 'Verified against a collected source.',
  inferred: 'Derived from policy text, not independently confirmed. Paths using it stay conditional.',
  stale: 'Source evidence is older than the freshness window.',
  unknown: 'Could not be determined.',
  invalidated: 'Known to be invalid or removed.',
}
const radiusOf = (n: GraphNode, deg: number) =>
  n.criticality === 'critical' ? 30 : Math.round(15 + Math.min(11, Math.sqrt(deg) * 3))

const Eyebrow = ({ children }: { children: ReactNode }) => (
  <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">{children}</div>
)

function Chip({ children, tone = 'slate' }: { children: ReactNode; tone?: Tone }) {
  return <span className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold ${TONES[tone]}`}>{children}</span>
}

const FANOUT = ['can_assume', 'can_pass_role', 'can_modify_policy']

export default function App() {
  const [scenarios, setScenarios] = useState<ScenarioSummary[]>([])
  const [scenarioId, setScenarioId] = useState('')
  const [graph, setGraph] = useState<GraphResponse | null>(null)
  const [paths, setPaths] = useState<PathsResponse | null>(null)
  const [overlays, setOverlays] = useState<OverlaysResponse | null>(null)
  const [state, setState] = useState<Load>('loading')
  const [sim, setSim] = useState<SimulationResponse | null>(null)
  const [simBusy, setSimBusy] = useState(false)
  const [simError, setSimError] = useState('')
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [pipeline, setPipeline] = useState<PipelineResponse | null>(null)
  const [showPipeline, setShowPipeline] = useState(false)
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [relFilter, setRelFilter] = useState('all')
  const [feasFilter, setFeasFilter] = useState('all')
  const [hideFanout, setHideFanout] = useState(true)
  const [reloadKey, setReloadKey] = useState(0)
  const [error, setError] = useState('')
  const [layers, setLayers] = useState<Record<LayerKey, boolean>>({ attack: false, fix: false, backup: false })
  const [view, setView] = useState<'overlay' | 'focus'>('overlay')
  const [showStructure, setShowStructure] = useState(false)
  const [focus, setFocus] = useState<Focus>(null)
  const [sel, setSel] = useState<Sel>(null)
  const [hoverId, setHoverId] = useState<string | null>(null)
  const hoverTimer = useRef<number | null>(null)

  // Debounced so brief boundary crossings can never cause a hover flicker loop.
  const setHover = (id: string | null) => {
    if (hoverTimer.current) window.clearTimeout(hoverTimer.current)
    hoverTimer.current = window.setTimeout(() => setHoverId(id), id ? 40 : 90)
  }

  useEffect(() => {
    getHealth().then(setHealth)
    getScenarios()
      .then((d) => { setScenarios(d); setScenarioId((cur) => cur || (d[0]?.scenario_id ?? '')) })
      .catch((e) => { setError(String(e)); setState('error') })
  }, [reloadKey])

  useEffect(() => {
    if (!scenarioId) return
    let cancelled = false
    setState('loading'); setGraph(null); setPaths(null); setOverlays(null); setPipeline(null)
    setFocus(null); setSel(null); setHoverId(null); setSim(null); setSimError('')
    setQuery(''); setTypeFilter('all'); setRelFilter('all'); setFeasFilter('all')
    Promise.all([getGraph(scenarioId), getPaths(scenarioId), getOverlays(scenarioId), getPipeline(scenarioId)])
      .then(([g, p, o, pl]) => {
        if (cancelled) return
        setGraph(g); setPaths(p); setOverlays(o); setPipeline(pl); setState('ready')
      })
      .catch((e) => { if (!cancelled) { setError(String(e)); setState('error') } })
    return () => { cancelled = true }
  }, [scenarioId, reloadKey])

  const nodeById = useMemo(() => new Map(graph?.nodes.map((n) => [n.entity_id, n]) ?? []), [graph])
  const edgeById = useMemo(() => new Map(graph?.edges.map((e) => [e.edge_id, e]) ?? []), [graph])
  const nameOf = (id: string) => nodeById.get(id)?.name ?? id

  const deg = useMemo(() => {
    const m = new Map<string, number>()
    graph?.edges.forEach((e) => {
      m.set(e.source_id, (m.get(e.source_id) ?? 0) + 1)
      m.set(e.target_id, (m.get(e.target_id) ?? 0) + 1)
    })
    return m
  }, [graph])

  // Computed once per scenario so toggling layers never moves anything.
  const positions = useMemo(() => {
    if (!graph) return {} as Record<string, { x: number; y: number }>
    return layout(
      graph.nodes.map((n) => ({ id: n.entity_id, r: radiusOf(n, deg.get(n.entity_id) ?? 0) })),
      graph.edges.map((e) => ({ source: e.source_id, target: e.target_id, weak: e.family === 'structure' })),
    )
  }, [graph, deg])

  const available: Record<LayerKey, boolean> = { attack: true, fix: overlays !== null, backup: overlays !== null }
  const lost = overlays?.access_lost ?? []
  const items = useMemo<Item[]>(() => {
    const out: Item[] = []
    paths?.paths.filter((p) => feasFilter === 'all' || p.feasibility === feasFilter).forEach((p) => out.push({
      layer: 'attack', id: p.path_id, title: p.node_ids.map((id) => nodeById.get(id)?.name ?? id).join(' → '),
      status: p.feasibility, note: p.explanations.join(' '), edge_ids: p.edge_ids,
    }))
    overlays?.fixes.forEach((o) => out.push({ layer: 'fix', id: o.id, title: o.label, status: o.status, note: o.note, edge_ids: o.edge_ids }))
    overlays?.backup_routes.forEach((o) => out.push({ layer: 'backup', id: o.id, title: o.label, status: o.status, note: o.note, edge_ids: o.edge_ids }))
    return out
  }, [paths, overlays, nodeById, feasFilter])
  const counts: Record<LayerKey, number> = {
    attack: items.filter((i) => i.layer === 'attack').length, fix: overlays?.fixes.length ?? 0, backup: overlays?.backup_routes.length ?? 0,
  }

  const layerEdges = useMemo(() => {
    const m = new Map<string, { layer: LayerKey; hot: boolean }>()
    const order: LayerKey[] = ['fix', 'backup', 'attack']
    for (const layer of order) {
      if (!layers[layer] || !available[layer]) continue
      for (const it of items) {
        if (it.layer !== layer) continue
        const hot = !focus || (focus.layer === it.layer && focus.id === it.id)
        it.edge_ids.forEach((id) => m.set(id, { layer, hot: hot || (m.get(id)?.hot ?? false) }))
      }
    }
    return m
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, layers, focus, overlays])

  const layerActive = layerEdges.size > 0
  const focusOnly = view === 'focus' && layerActive
  const layerNodes = useMemo(() => {
    const s = new Set<string>()
    layerEdges.forEach((_, id) => {
      const e = edgeById.get(id)
      if (e) { s.add(e.source_id); s.add(e.target_id) }
    })
    return s
  }, [layerEdges, edgeById])

  const entryIds = useMemo(() => new Set(paths?.paths.map((p) => p.entry_node_id) ?? []), [paths])
  const targetIds = useMemo(() => new Set(paths?.paths.map((p) => p.target_node_id) ?? []), [paths])

  const adminHolders = useMemo(() => {
    const admin = new Set(graph?.nodes.filter((n) => n.name === 'AdministratorAccess').map((n) => n.entity_id) ?? [])
    return new Set(graph?.edges.filter((e) => e.relation_type === 'has_policy' && admin.has(e.target_id)).map((e) => e.source_id) ?? [])
  }, [graph])

  const visibleEdges = useMemo(() => {
    if (!graph) return [] as GraphEdge[]
    if (focusOnly) return graph.edges.filter((e) => layerEdges.has(e.edge_id))
    return graph.edges.filter((e) => {
      if (layerEdges.has(e.edge_id)) return true // a layer edge is never hidden by a filter
      if (!showStructure && e.family === 'structure') return false
      if (relFilter !== 'all' && e.relation_type !== relFilter) return false
      if (hideFanout && adminHolders.has(e.source_id) && FANOUT.includes(e.relation_type)) return false
      return true
    })
  }, [graph, focusOnly, layerEdges, showStructure, relFilter, hideFanout, adminHolders])

  const hoverNbrs = useMemo(() => {
    if (!hoverId) return null
    const s = new Set<string>([hoverId])
    visibleEdges.forEach((e) => {
      if (e.source_id === hoverId) s.add(e.target_id)
      if (e.target_id === hoverId) s.add(e.source_id)
    })
    return s
  }, [hoverId, visibleEdges])

  const q = query.trim().toLowerCase()
  const matchIds = useMemo(() => {
    if (!graph || (!q && typeFilter === 'all')) return null
    return new Set(graph.nodes
      .filter((n) => (!q || n.name.toLowerCase().includes(q)) && (typeFilter === 'all' || n.entity_type === typeFilter))
      .map((n) => n.entity_id))
  }, [graph, q, typeFilter])

  const { rfNodes, rfEdges } = useMemo(() => {
    if (!graph) return { rfNodes: [] as Node[], rfEdges: [] as Edge[] }
    const touched = new Set<string>()
    visibleEdges.forEach((e) => { touched.add(e.source_id); touched.add(e.target_id) })
    const vnodes = graph.nodes.filter((n) => touched.has(n.entity_id) || (!focusOnly && !deg.has(n.entity_id)))

    const rfNodes: Node[] = vnodes.map((n) => {
      const id = n.entity_id
      const r = radiusOf(n, deg.get(id) ?? 0)
      const p = positions[id] ?? { x: 0, y: 0 }
      let dim = 1
      if (hoverNbrs) dim = hoverNbrs.has(id) ? 1 : 0.4
      else if (matchIds) dim = matchIds.has(id) ? 1 : 0.2
      else if (layerActive) dim = layerNodes.has(id) ? 1 : 0.3
      const badge = layers.attack ? (targetIds.has(id) ? 'target' : entryIds.has(id) ? 'entry' : null) : null
      const data: CircleData = { e: n, r, dim, selected: sel?.kind === 'node' && sel.id === id, badge }
      return { id, type: 'circle', position: { x: p.x - r, y: p.y - r }, data, draggable: false }
    })

    const plain: Edge[] = []
    const painted: Edge[] = []
    visibleEdges.forEach((e) => {
      const L = layerEdges.get(e.edge_id)
      const incident = hoverId !== null && (e.source_id === hoverId || e.target_id === hoverId)
      const isSel = sel?.kind === 'edge' && sel.id === e.edge_id
      let stroke = e.family === 'authorization' ? '#94a3b8' : '#cbd5e1'
      let width = e.family === 'authorization' ? 1.3 : 1
      let opacity = layerActive ? 0.1 : 0.7
      let dash: string | undefined = e.family === 'authorization' ? undefined : '3 4'
      let className: string | undefined
      if (L) {
        stroke = LAYER[L.layer].color
        width = L.hot ? 2.8 : 1.6
        opacity = L.hot ? 1 : 0.3
        dash = L.layer === 'fix' ? '6 5' : undefined
        className = `edge-${L.layer}${L.hot && focus ? ' edge-flow' : ''}`
      }
      if (hoverId) opacity = incident ? Math.max(opacity, 0.9) : opacity * 0.5
      if (isSel) { width += 1.5; opacity = 1 }
      // Labels only on a selected edge or a focused layer item, never on hover (they piled up).
      const showLabel = isSel || (!!L?.hot && !!focus)
      const edge: Edge = {
        id: e.edge_id, source: e.source_id, target: e.target_id, type: 'floating',
        style: { stroke, strokeWidth: width, opacity, strokeDasharray: dash },
        markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
        className, interactionWidth: 10,
        data: { label: showLabel ? pretty(e.relation_type) : undefined },
      }
      // No zIndex: edges stay under nodes. Painted layer edges are drawn last instead.
      ;(L ? painted : plain).push(edge)
    })
    return { rfNodes, rfEdges: [...plain, ...painted] }
  }, [graph, visibleEdges, positions, deg, focusOnly, hoverNbrs, hoverId, layerActive, layerNodes,
      layerEdges, layers.attack, entryIds, targetIds, sel, focus, matchIds])

  const runSim = async () => {
    setSimBusy(true); setSimError('')
    try {
      const ids = focus?.layer === 'fix' ? [focus.id] : null
      setSim(await simulateRemediation(scenarioId, ids))
    } catch (e) {
      setSim(null); setSimError(String(e))
    } finally {
      setSimBusy(false)
    }
  }

  const toggleLayer = (k: LayerKey) => {
    setLayers((l) => ({ ...l, [k]: !l[k] }))
    if (focus?.layer === k) setFocus(null)
  }
  const activeKey = (Object.keys(layers) as LayerKey[]).filter((k) => layers[k]).join('+')

  // ---------- inspector ----------
  const inspector = (() => {
    if (!graph || !sel) return null
    if (sel.kind === 'node') {
      const n = nodeById.get(sel.id)
      if (!n) return null
      const { color, label, Icon } = styleOf(n.entity_type)
      const incident = graph.edges.filter((e) => e.source_id === n.entity_id || e.target_id === n.entity_id)
      const prim = Object.entries(n.attributes).filter(([, v]) => ['string', 'number', 'boolean'].includes(typeof v))
      return (
        <>
          <div className="flex items-start gap-3">
            <div className="grid h-11 w-11 shrink-0 place-items-center rounded-full bg-white"
              style={{ boxShadow: `0 0 0 1.5px ${color}99, 0 8px 18px ${color}33` }}>
              <Icon size={20} color={color} strokeWidth={1.6} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="break-words text-[15px] font-semibold leading-tight tracking-tight text-slate-900">{n.name}</div>
              <div className="mt-1.5 flex flex-wrap gap-1">
                <Chip>{label}</Chip>
                {n.criticality && <Chip tone={n.criticality === 'critical' ? 'red' : 'amber'}>{n.criticality}</Chip>}
                <Chip tone="blue">class: {n.identity_class.toLowerCase()}</Chip>
              </div>
            </div>
            <button onClick={() => setSel(null)} className="rounded-full p-1.5 text-slate-400 transition hover:bg-slate-900/5"><X size={15} /></button>
          </div>
          <div className="mt-3 break-all rounded-xl bg-slate-900/[0.04] p-2.5 font-mono text-[10px] text-slate-600">{n.entity_id}</div>
          {prim.length > 0 && (
            <dl className="mt-3 space-y-1 text-xs">
              {prim.map(([k, v]) => (
                <div key={k} className="flex justify-between gap-3">
                  <dt className="text-slate-500">{k}</dt><dd className="break-all text-right text-slate-800">{String(v)}</dd>
                </div>
              ))}
            </dl>
          )}
          <div className="mt-5"><Eyebrow>Connections ({incident.length})</Eyebrow></div>
          <div className="mt-1.5 space-y-0.5">
            {incident.slice(0, 14).map((e) => {
              const out = e.source_id === n.entity_id
              return (
                <button key={e.edge_id} onClick={() => setSel({ kind: 'edge', id: e.edge_id })}
                  className="flex w-full items-center gap-2 rounded-xl px-2 py-1.5 text-left text-xs transition hover:bg-slate-900/5">
                  <span className="text-slate-400">{out ? '→' : '←'}</span>
                  <span className="truncate text-slate-800">{nameOf(out ? e.target_id : e.source_id)}</span>
                  <span className="ml-auto shrink-0 text-[10px] text-slate-500">{pretty(e.relation_type)}</span>
                </button>
              )
            })}
            {incident.length > 14 && <div className="px-2 text-[11px] text-slate-400">+{incident.length - 14} more</div>}
          </div>
          <details className="mt-4 text-xs"><summary className="cursor-pointer text-slate-500">Raw data</summary>
            <pre className="mt-2 whitespace-pre-wrap text-[10px] text-slate-600">{JSON.stringify(n, null, 2)}</pre></details>
        </>
      )
    }
    const e = edgeById.get(sel.id)
    if (!e) return null
    const inLayers = items.filter((i) => i.edge_ids.includes(e.edge_id))
    const cond = Object.entries(e.conditions)
    return (
      <>
        <div className="flex items-start gap-2">
          <div className="min-w-0 flex-1">
            <Eyebrow>Relationship</Eyebrow>
            <div className="mt-1.5 text-[15px] font-semibold leading-snug tracking-tight text-slate-900">
              <button className="underline decoration-slate-300 decoration-dotted underline-offset-2" onClick={() => setSel({ kind: 'node', id: e.source_id })}>{nameOf(e.source_id)}</button>
              <span className="mx-1.5 text-slate-300">→</span>
              <button className="underline decoration-slate-300 decoration-dotted underline-offset-2" onClick={() => setSel({ kind: 'node', id: e.target_id })}>{nameOf(e.target_id)}</button>
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              <Chip tone="purple">{pretty(e.relation_type)}</Chip>
              <Chip>{e.family}</Chip>
              <Chip tone={statusTone(e.status)}>{e.status}</Chip>
            </div>
          </div>
          <button onClick={() => setSel(null)} className="rounded-full p-1.5 text-slate-400 transition hover:bg-slate-900/5"><X size={15} /></button>
        </div>
        <p className="mt-3 text-xs leading-relaxed text-slate-600">{STATUS_HELP[e.status] ?? ''}</p>
        <div className="mt-5"><Eyebrow>Conditions</Eyebrow></div>
        {cond.length === 0
          ? <p className="mt-1.5 text-xs text-slate-600">None recorded.</p>
          : <div className="mt-1.5 space-y-1">
              {cond.map(([k, v]) => <div key={k} className="rounded-xl bg-amber-500/10 p-2.5 text-xs text-amber-900"><b>{k}</b>: {JSON.stringify(v)}</div>)}
              <p className="text-[11px] text-slate-500">Recorded but not yet evaluated, so this edge is treated as conditional.</p>
            </div>}
        <div className="mt-5"><Eyebrow>Evidence</Eyebrow></div>
        <div className="mt-1.5 space-y-1">
          {e.evidence_ids.length === 0 && <p className="text-xs text-slate-600">No evidence IDs.</p>}
          {e.evidence_ids.map((x) => <div key={x} className="break-all rounded-xl bg-slate-900/[0.04] p-2.5 font-mono text-[10px] text-slate-600">{x}</div>)}
        </div>
        {inLayers.length > 0 && (
          <>
            <div className="mt-5"><Eyebrow>Part of</Eyebrow></div>
            <div className="mt-1.5 space-y-0.5">
              {inLayers.map((i) => (
                <button key={i.layer + i.id}
                  onClick={() => { setLayers((l) => ({ ...l, [i.layer]: true })); setFocus({ layer: i.layer, id: i.id }) }}
                  className="flex w-full items-center gap-2 rounded-xl px-2 py-1.5 text-left text-xs transition hover:bg-slate-900/5">
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: LAYER[i.layer].color }} />
                  <span className="truncate">{i.title}</span>
                </button>
              ))}
            </div>
          </>
        )}
        <details className="mt-4 text-xs"><summary className="cursor-pointer text-slate-500">Raw data</summary>
          <pre className="mt-2 whitespace-pre-wrap text-[10px] text-slate-600">{JSON.stringify(e, null, 2)}</pre></details>
      </>
    )
  })()

  const presentTypes = graph ? Array.from(new Set(graph.nodes.map((n) => n.entity_type))) : []
  const relationTypes = graph ? Array.from(new Set(graph.edges.map((e) => e.relation_type))).sort() : []
  const sel_cls = 'mt-1.5 w-full rounded-xl border border-slate-900/10 bg-white/80 px-2 py-1.5 text-xs outline-none'
  const overlayWarnings = overlays?.warnings ?? []
  const showOverlayNotes = (layers.fix || layers.backup) && overlays !== null

  return (
    <div className="relative h-screen w-screen overflow-hidden text-sm">
      {/* canvas: the whole map, always */}
      <div className="canvas-bg absolute inset-0">
        {graph && (
          <ReactFlow
            key={`${scenarioId}|${view}|${focusOnly ? activeKey : ''}`}
            nodes={rfNodes} edges={rfEdges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
            fitView fitViewOptions={{ padding: 0.18 }} minZoom={0.1} maxZoom={2.5}
            nodesDraggable={false} nodesConnectable={false} elevateEdgesOnSelect={false}
            onNodeClick={(_, n) => setSel({ kind: 'node', id: n.id })}
            onEdgeClick={(_, e) => setSel({ kind: 'edge', id: e.id })}
            onPaneClick={() => setSel(null)}
            onNodeMouseEnter={(_, n) => setHover(n.id)}
            onNodeMouseLeave={() => setHover(null)}
            style={{ background: 'transparent' }}
          >
            <Background variant={BackgroundVariant.Dots} gap={26} size={1.2} color="#d9dde8" />
            <Controls position="bottom-center" orientation="horizontal" showInteractive={false} />
            <MiniMap pannable zoomable position="bottom-right" maskColor="rgba(245,246,250,.7)"
              style={{ width: 150, height: 100 }} nodeStrokeWidth={3}
              nodeColor={(n) => ((n.data as CircleData | undefined)?.e
                ? styleOf((n.data as CircleData).e.entity_type).color : '#94a3b8')} />
          </ReactFlow>
        )}
      </div>

      {state === 'loading' && (
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <div className={`${card} px-6 py-3 text-slate-600`}>Loading scenario…</div>
        </div>
      )}
      {state === 'error' && (
        <div className="absolute inset-0 grid place-items-center">
          <div className={`${card} max-w-md p-6`}>
            <div className="text-[15px] font-semibold tracking-tight text-rose-700">Can't reach the API</div>
            <p className="mt-1.5 text-slate-600">{error}. Start it from the repo root with <code>python -m uvicorn backend.api.main:app --port 8000</code>.</p>
            <button onClick={() => { setError(''); setState('loading'); setReloadKey((k) => k + 1) }}
              className="mt-3 rounded-2xl bg-slate-900 px-4 py-2 text-xs font-semibold text-white">Retry</button>
          </div>
        </div>
      )}

      {state === 'ready' && graph && graph.nodes.length === 0 && (
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <div className={`${card} px-6 py-3 text-slate-600`}>This scenario has no entities.</div>
        </div>
      )}

      {/* floating UI */}
      <div className="pointer-events-none absolute inset-0 z-10">
        {/* left column */}
        <div className="absolute bottom-52 left-4 top-4 flex w-72 flex-col gap-3">
          <div className={`${card} pointer-events-auto p-4`}>
            <div className="flex items-center gap-2.5">
              <div className="grid h-9 w-9 place-items-center rounded-2xl bg-gradient-to-b from-slate-700 to-slate-950 text-xs font-bold text-white shadow-md">H</div>
              <div>
                <div className="text-[15px] font-semibold leading-tight tracking-tight">HardCoded</div>
                <div className="text-[11px] text-slate-500">NHI attack-path inspector</div>
              </div>
            </div>
            <select className="mt-3.5 w-full rounded-xl border border-slate-900/10 bg-white/80 px-2.5 py-2 text-xs outline-none focus:ring-2 focus:ring-indigo-400/40"
              value={scenarioId} onChange={(e) => setScenarioId(e.target.value)}>
              {scenarios.map((s) => <option key={s.scenario_id} value={s.scenario_id}>{s.scenario_id}</option>)}
            </select>
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search nodes…"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && matchIds) {
                  const first = [...matchIds][0]
                  if (first) setSel({ kind: 'node', id: first })
                }
              }}
              className="mt-2 w-full rounded-xl border border-slate-900/10 bg-white/80 px-2.5 py-2 text-xs outline-none focus:ring-2 focus:ring-indigo-400/40" />
            <details className="mt-2 text-xs text-slate-600">
              <summary className="cursor-pointer text-slate-500">Filters</summary>
              <select className={sel_cls} value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
                <option value="all">All node types</option>
                {presentTypes.map((t) => <option key={t} value={t}>{styleOf(t).label}</option>)}
              </select>
              <select className={sel_cls} value={relFilter} onChange={(e) => setRelFilter(e.target.value)}>
                <option value="all">All relations</option>
                {relationTypes.map((r) => <option key={r} value={r}>{pretty(r)}</option>)}
              </select>
              <select className={sel_cls} value={feasFilter} onChange={(e) => setFeasFilter(e.target.value)}>
                <option value="all">All path feasibility</option>
                <option value="feasible_under_model">feasible under model</option>
                <option value="conditional">conditional</option>
                <option value="blocked">blocked</option>
              </select>
              <label className="mt-2 flex cursor-pointer items-center gap-2">
                <input type="checkbox" checked={hideFanout} onChange={(e) => setHideFanout(e.target.checked)} />
                hide admin fan-out edges
              </label>
              <p className="mt-1.5 text-[10px] leading-snug text-slate-400">
                Identity class, owner and environment filters need ownership data that is not available yet.
              </p>
            </details>
            {graph && paths && (
              <div className="mt-3.5 grid grid-cols-3 text-center">
                {[['nodes', graph.nodes.length], ['edges', graph.edges.length], ['paths', paths.paths.length]].map(([k, v]) => (
                  <div key={k}>
                    <div className="text-xl font-semibold tracking-tight">{v}</div>
                    <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">{k}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="mt-3.5 rounded-full bg-amber-500/15 px-3 py-1 text-center text-[10px] font-bold uppercase tracking-[0.12em] text-amber-900">
              Simulation only · no AWS change applied
            </div>
          </div>

          {(Object.keys(layers) as LayerKey[]).some((k) => layers[k]) && (
            <div className={`${card} pointer-events-auto min-h-0 flex-1 overflow-auto p-3.5`}>
              {(Object.keys(LAYER) as LayerKey[]).filter((k) => layers[k]).map((k) => {
                const list = items.filter((i) => i.layer === k)
                return (
                  <div key={k} className="mb-4 last:mb-0">
                    <div className="mb-1.5 flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full" style={{ background: LAYER[k].color, boxShadow: `0 0 8px ${LAYER[k].color}` }} />
                      <Eyebrow>{LAYER[k].label} ({list.length})</Eyebrow>
                    </div>
                    {k === 'attack' && <p className="mb-2 text-[11px] leading-snug text-slate-500">Potential routes under the model, not evidence an attack occurred.</p>}
                    {k === 'fix' && <p className="mb-2 text-[11px] leading-snug text-slate-500">Proposed changes, simulated only. Nothing is applied to AWS.</p>}
                    {list.length === 0 && (
                      <p className="text-xs text-slate-500">
                        {!available[k] ? 'Not available from the API yet.'
                          : k === 'backup' && lost.length > 0 ? 'No verified backup route (see below).'
                          : 'Nothing found within the search limits.'}
                      </p>
                    )}
                    {list.map((it) => {
                      const on = focus?.layer === it.layer && focus.id === it.id
                      return (
                        <button key={it.id} onClick={() => setFocus(on ? null : { layer: it.layer, id: it.id })}
                          className={`mb-1.5 block w-full rounded-2xl border p-2.5 text-left transition ${on ? 'bg-white shadow-md' : 'border-transparent hover:bg-white/70'}`}
                          style={on ? { borderColor: LAYER[k].color + '88' } : undefined}>
                          <div className="line-clamp-2 text-xs font-medium text-slate-800">{it.title}</div>
                          <div className="mt-1.5"><Chip tone={it.layer === 'attack' ? feasTone(it.status) : it.layer === 'backup' ? 'green' : 'slate'}>{pretty(it.status)}</Chip></div>
                          {on && it.note && <p className="mt-2 text-[11px] leading-snug text-slate-600">{it.note}</p>}
                        </button>
                      )
                    })}
                    {k === 'fix' && list.length > 0 && (
                      <button onClick={runSim} disabled={simBusy}
                        className="mt-1 w-full rounded-2xl bg-purple-600 px-3 py-2 text-xs font-semibold text-white shadow transition hover:bg-purple-700 disabled:opacity-60">
                        {simBusy ? 'Simulating…' : focus?.layer === 'fix' ? 'Simulate this fix' : 'Simulate all fixes'}
                      </button>
                    )}
                    {k === 'fix' && simError && <p className="mt-1.5 text-[11px] text-rose-700">{simError}</p>}
                    {k === 'backup' && lost.map((l) => (
                      <button key={l.id} onClick={() => l.node_ids?.[0] && setSel({ kind: 'node', id: l.node_ids[0] })}
                        className="mb-1.5 block w-full rounded-2xl bg-amber-500/12 p-2.5 text-left transition hover:bg-amber-500/20">
                        <div className="flex items-center gap-1.5">
                          <Chip tone="amber">access lost</Chip>
                        </div>
                        <div className="mt-1.5 text-xs font-medium text-amber-900">{l.label.replace('No verified backup | ', '')}</div>
                        <p className="mt-1 text-[11px] leading-snug text-amber-900/80">{l.note}</p>
                      </button>
                    ))}
                  </div>
                )
              })}
              {paths && layers.attack && (
                <details className="mt-2 text-[11px] text-slate-500"><summary className="cursor-pointer">Assumptions</summary>
                  <ul className="ml-4 mt-1 list-disc">{paths.assumptions.map((a) => <li key={a}>{a}</li>)}</ul></details>
              )}
            </div>
          )}
        </div>

        {/* top center: layers + view */}
        <div className="absolute left-1/2 top-4 flex -translate-x-1/2 items-center gap-2.5">
          <div className={`${card} pointer-events-auto flex items-center gap-1 p-1.5`}>
            <span className="px-3"><Eyebrow>Layers</Eyebrow></span>
            {(Object.keys(LAYER) as LayerKey[]).map((k) => {
              const on = layers[k] && available[k]
              return (
                <button key={k} disabled={!available[k]} onClick={() => toggleLayer(k)}
                  title={available[k] ? '' : 'Overlays unavailable: the /overlays endpoint did not respond'}
                  className={`flex items-center gap-2 whitespace-nowrap rounded-2xl px-3.5 py-1.5 text-xs font-medium transition ${
                    on ? 'text-white' : available[k] ? 'text-slate-600 hover:bg-slate-900/5' : 'cursor-not-allowed text-slate-300'}`}
                  style={on ? { background: LAYER[k].color, boxShadow: `0 6px 16px -4px ${LAYER[k].color}99` } : undefined}>
                  {LAYER[k].label}
                  <span className={`rounded-full px-1.5 text-[10px] ${on ? 'bg-white/25' : 'bg-slate-900/5 text-slate-500'}`}>
                    {available[k] ? counts[k] : 'n/a'}
                  </span>
                </button>
              )
            })}
          </div>
          <div className={`${card} pointer-events-auto flex p-1.5`}>
            {(['overlay', 'focus'] as const).map((v) => (
              <button key={v} onClick={() => setView(v)}
                className={`whitespace-nowrap rounded-2xl px-3.5 py-1.5 text-xs font-medium transition ${view === v ? 'bg-slate-900 text-white shadow' : 'text-slate-600 hover:bg-slate-900/5'}`}>
                {v === 'overlay' ? 'Whole map' : 'Focus layer'}
              </button>
            ))}
          </div>
          <label className={`${card} pointer-events-auto flex cursor-pointer items-center gap-2 whitespace-nowrap px-3.5 py-2.5 text-xs text-slate-600`}>
            <input type="checkbox" checked={showStructure} onChange={(e) => setShowStructure(e.target.checked)} />
            policies &amp; groups
          </label>
          <button onClick={() => setShowPipeline((v) => !v)}
            className={`${card} pointer-events-auto whitespace-nowrap px-3.5 py-2.5 text-xs font-medium ${showPipeline ? 'text-indigo-700' : 'text-slate-600'}`}>
            Pipeline
          </button>
        </div>

        {/* right column */}
        <div className="absolute bottom-44 right-4 top-4 flex w-80 flex-col items-end gap-3">
          {graph && (
            <div className={`${card} pointer-events-auto flex items-center gap-3 px-3.5 py-2 text-[11px] text-slate-600`}>
              <span>version <code className="text-slate-800">{graph.graph_version}</code></span>
              <Chip>{graph.data_mode}</Chip>
              {health
                ? <Chip tone={health.neo4j === 'connected' ? 'green' : 'slate'}>neo4j: {pretty(health.neo4j)}</Chip>
                : <Chip tone="amber">health unknown</Chip>}
            </div>
          )}
          {health && ['unavailable', 'error'].includes(health.neo4j) && (
            <div className="pointer-events-auto w-full rounded-2xl bg-amber-100/90 p-3 text-xs text-amber-900 shadow-lg backdrop-blur">
              Neo4j is unavailable. Showing the in-memory fixture graph; nothing is written to the database.
            </div>
          )}
          {paths?.search.truncated && (
            <div className="pointer-events-auto w-full rounded-2xl bg-rose-100/90 p-3 text-xs text-rose-900 shadow-lg backdrop-blur">
              Path search truncated ({paths.search.truncation_reason}). More paths may exist; no path shown is not proof of safety.
            </div>
          )}
          {showOverlayNotes && overlays?.search_truncated && (
            <div className="pointer-events-auto w-full rounded-2xl bg-rose-100/90 p-3 text-xs text-rose-900 shadow-lg backdrop-blur">
              Because the search was truncated, backup routes are not shown as verified and fixes are partial.
            </div>
          )}
          {showOverlayNotes && overlayWarnings.length > 0 && (
            <div className="pointer-events-auto w-full rounded-2xl bg-amber-100/90 p-3 text-xs text-amber-900 shadow-lg backdrop-blur">
              {overlayWarnings.length} fix/backup note(s). <details><summary className="cursor-pointer">Show</summary>
                <ul className="ml-4 mt-1 list-disc text-[11px]">{overlayWarnings.map((w) => <li key={w}>{w}</li>)}</ul></details>
            </div>
          )}
          {graph && graph.warnings.length > 0 && (
            <div className="pointer-events-auto w-full rounded-2xl bg-amber-100/90 p-3 text-xs text-amber-900 shadow-lg backdrop-blur">
              {graph.warnings.length} ingestion warning(s). <details><summary className="cursor-pointer">Show</summary>
                <pre className="mt-1 whitespace-pre-wrap text-[10px]">{graph.warnings.join('\n')}</pre></details>
            </div>
          )}
          {sim && (
            <div className={`${card} pointer-events-auto min-h-0 w-full overflow-auto p-4`}>
              <div className="flex items-start justify-between gap-2">
                <div>
                  <Eyebrow>Simulation</Eyebrow>
                  <div className="mt-1 text-[15px] font-semibold tracking-tight text-slate-900">
                    {sim.fixes_simulated.length} fix{sim.fixes_simulated.length === 1 ? '' : 'es'} simulated
                  </div>
                </div>
                <button onClick={() => setSim(null)} className="rounded-full p-1.5 text-slate-400 transition hover:bg-slate-900/5"><X size={15} /></button>
              </div>
              <div className="mt-3 rounded-2xl bg-amber-500/15 p-2.5 text-[11px] leading-snug text-amber-900">
                <b>Human approval required.</b> {sim.approval.reason} Nothing is applied to AWS ({sim.execution_mode.toLowerCase().replace('_', ' ')}).
              </div>
              <div className="mt-4 grid grid-cols-3 text-center">
                {[['before', sim.paths.before], ['removed', sim.paths.removed.length], ['residual', sim.paths.residual.length]].map(([k, v]) => (
                  <div key={k}>
                    <div className="text-xl font-semibold tracking-tight">{v}</div>
                    <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">{k}</div>
                  </div>
                ))}
              </div>
              {sim.paths.residual_is_lower_bound && (
                <p className="mt-2 rounded-xl bg-rose-100/90 p-2 text-[11px] text-rose-900">
                  Search was truncated, so residual paths are a lower bound. Zero residual is not proof of safety.
                </p>
              )}
              {sim.paths.removed.length > 0 && (
                <>
                  <div className="mt-4"><Eyebrow>Removed ({sim.paths.removed.length})</Eyebrow></div>
                  <div className="mt-1.5 space-y-1">
                    {sim.paths.removed.map((p) => <div key={p.path_id} className="rounded-xl bg-emerald-500/10 p-2 text-[11px] text-emerald-900">{p.route}</div>)}
                  </div>
                </>
              )}
              {sim.paths.residual.length > 0 && (
                <>
                  <div className="mt-4"><Eyebrow>Still reachable ({sim.paths.residual.length})</Eyebrow></div>
                  <div className="mt-1.5 space-y-1">
                    {sim.paths.residual.map((p) => <div key={p.path_id} className="rounded-xl bg-rose-500/10 p-2 text-[11px] text-rose-900">{p.route}</div>)}
                  </div>
                </>
              )}
              <div className="mt-4"><Eyebrow>Legitimate access</Eyebrow></div>
              {!sim.access.requirements_loaded && <p className="mt-1.5 text-[11px] text-slate-600">No access requirements for this scenario, so impact was not checked.</p>}
              <div className="mt-1.5 space-y-1">
                {sim.access.preserved_via_backup.map((a) => (
                  <div key={a.principal + a.resource} className="rounded-xl bg-emerald-500/10 p-2 text-[11px] text-emerald-900">
                    <b>Preserved:</b> {a.principal} → {a.resource}<br />via {a.route}
                  </div>
                ))}
                {sim.access.lost.map((a) => (
                  <div key={a.principal + a.resource} className="rounded-xl bg-amber-500/15 p-2 text-[11px] text-amber-900">
                    <b>Lost:</b> {a.principal} → {a.resource}<br />{a.reason}
                  </div>
                ))}
                {sim.access.requirements_loaded && sim.access.preserved_via_backup.length + sim.access.lost.length === 0 &&
                  <p className="text-[11px] text-slate-600">No listed access is affected by these fixes.</p>}
              </div>
              {sim.warnings.length > 0 && (
                <ul className="ml-4 mt-3 list-disc text-[10px] text-slate-500">{sim.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
              )}
              <div className="mt-3 font-mono text-[10px] text-slate-400">{sim.run_id} · {sim.graph_version}</div>
            </div>
          )}
          {inspector && <div key={sel?.kind + (sel?.id ?? '')} className={`${card} pointer-events-auto min-h-0 w-full overflow-auto p-4`}>{inspector}</div>}
        </div>

        {showPipeline && (
          <div className={`${card} pointer-events-auto absolute bottom-16 left-[21rem] right-[21rem] max-h-[45vh] overflow-auto p-4`}>
            <div className="flex items-center justify-between">
              <Eyebrow>Pipeline</Eyebrow>
              <button onClick={() => setShowPipeline(false)} className="rounded-full p-1.5 text-slate-400 transition hover:bg-slate-900/5"><X size={15} /></button>
            </div>
            {!pipeline && <p className="mt-2 text-xs text-slate-600">Pipeline details are unavailable from the API.</p>}
            {pipeline && (
              <>
                <div className="mt-2 flex items-stretch gap-1 overflow-x-auto pb-1">
                  {pipeline.stages.map((st, i) => (
                    <div key={st.key} className="flex items-center gap-1">
                      <div className="w-36 shrink-0 rounded-2xl bg-white/70 p-2.5">
                        <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">{st.label}</div>
                        <div className="mt-0.5 text-lg font-semibold tracking-tight text-slate-900">{st.count ?? '—'}</div>
                        <div className="text-[10px] text-slate-500">{st.unit}</div>
                        <div className="mt-1 text-[10px] leading-snug text-slate-600">{st.detail}</div>
                        {st.warnings.length > 0 && (
                          <details className="mt-1 text-[10px] text-amber-800">
                            <summary className="cursor-pointer">{st.warnings.length} warning(s)</summary>
                            <ul className="ml-3 list-disc">{st.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
                          </details>
                        )}
                      </div>
                      {i < pipeline.stages.length - 1 && <span className="text-slate-300">→</span>}
                    </div>
                  ))}
                </div>
                <div className="mt-3"><Eyebrow>What Neo4j is doing</Eyebrow></div>
                <p className="mt-1 text-[11px] leading-snug text-slate-600">{pipeline.neo4j.explanation}</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  <Chip>{pipeline.neo4j.would_write.nodes} nodes</Chip>
                  {Object.entries(pipeline.neo4j.would_write.relationships_by_type).map(([k, v]) => <Chip key={k}>{k} {v}</Chip>)}
                  {Object.entries(pipeline.neo4j.would_write.overlays).map(([k, v]) => <Chip key={k} tone="purple">{k} {v}</Chip>)}
                </div>
                <p className="mt-1.5 text-[10px] text-slate-400">Counts the exporter would write for this scenario. Not connected in fixture mode.</p>
              </>
            )}
          </div>
        )}

        {/* legend */}
        {graph && (
          <div className={`${card} pointer-events-auto absolute bottom-4 left-4 w-72 p-3.5`}>
            <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
              {presentTypes.map((t) => {
                const { color, label, Icon } = styleOf(t)
                return <div key={t} className="flex items-center gap-1.5 text-[11px] text-slate-600"><Icon size={12} color={color} strokeWidth={1.8} />{label}{TYPE_STYLE[t] ? '' : ''}</div>
              })}
            </div>
            <div className="mt-2.5 flex flex-wrap gap-x-3 gap-y-1 border-t border-slate-900/10 pt-2.5 text-[10px] text-slate-500">
              <span className="flex items-center gap-1"><i className="inline-block h-0.5 w-4 bg-slate-400" />authorization</span>
              <span className="flex items-center gap-1"><i className="inline-block w-4 border-t-2 border-dotted border-slate-300" />context</span>
              <span className="flex items-center gap-1"><i className="inline-block h-0.5 w-4 bg-red-500" />attack</span>
              <span className="flex items-center gap-1"><i className="inline-block w-4 border-t-2 border-dashed border-purple-500" />fix</span>
              <span className="flex items-center gap-1"><i className="inline-block h-0.5 w-4 bg-emerald-500" />backup</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
