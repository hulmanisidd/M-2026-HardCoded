import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  Background, BackgroundVariant, Controls, MarkerType, MiniMap, ReactFlow,
  type Edge, type Node,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { X } from 'lucide-react'
import { getGraph, getOverlays, getPaths, getScenarios } from './api'
import { layout } from './layout'
import { edgeTypes, nodeTypes, styleOf, TYPE_STYLE, type CircleData } from './graphParts'
import type {
  GraphEdge, GraphNode, GraphResponse, OverlaysResponse, PathsResponse, ScenarioSummary,
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

export default function App() {
  const [scenarios, setScenarios] = useState<ScenarioSummary[]>([])
  const [scenarioId, setScenarioId] = useState('')
  const [graph, setGraph] = useState<GraphResponse | null>(null)
  const [paths, setPaths] = useState<PathsResponse | null>(null)
  const [overlays, setOverlays] = useState<OverlaysResponse | null>(null)
  const [state, setState] = useState<Load>('loading')
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
    getScenarios()
      .then((d) => { setScenarios(d); setScenarioId(d[0]?.scenario_id ?? '') })
      .catch((e) => { setError(String(e)); setState('error') })
  }, [])

  useEffect(() => {
    if (!scenarioId) return
    let cancelled = false
    setState('loading'); setGraph(null); setPaths(null); setOverlays(null)
    setFocus(null); setSel(null); setHoverId(null)
    Promise.all([getGraph(scenarioId), getPaths(scenarioId), getOverlays(scenarioId)])
      .then(([g, p, o]) => {
        if (cancelled) return
        setGraph(g); setPaths(p); setOverlays(o); setState('ready')
      })
      .catch((e) => { if (!cancelled) { setError(String(e)); setState('error') } })
    return () => { cancelled = true }
  }, [scenarioId])

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
    paths?.paths.forEach((p) => out.push({
      layer: 'attack', id: p.path_id, title: p.node_ids.map((id) => nodeById.get(id)?.name ?? id).join(' → '),
      status: p.feasibility, note: p.explanations.join(' '), edge_ids: p.edge_ids,
    }))
    overlays?.fixes.forEach((o) => out.push({ layer: 'fix', id: o.id, title: o.label, status: o.status, note: o.note, edge_ids: o.edge_ids }))
    overlays?.backup_routes.forEach((o) => out.push({ layer: 'backup', id: o.id, title: o.label, status: o.status, note: o.note, edge_ids: o.edge_ids }))
    return out
  }, [paths, overlays, nodeById])
  const counts: Record<LayerKey, number> = {
    attack: paths?.paths.length ?? 0, fix: overlays?.fixes.length ?? 0, backup: overlays?.backup_routes.length ?? 0,
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

  const visibleEdges = useMemo(() => {
    if (!graph) return [] as GraphEdge[]
    if (focusOnly) return graph.edges.filter((e) => layerEdges.has(e.edge_id))
    return graph.edges.filter((e) => showStructure || e.family !== 'structure')
  }, [graph, focusOnly, layerEdges, showStructure])

  const hoverNbrs = useMemo(() => {
    if (!hoverId) return null
    const s = new Set<string>([hoverId])
    visibleEdges.forEach((e) => {
      if (e.source_id === hoverId) s.add(e.target_id)
      if (e.target_id === hoverId) s.add(e.source_id)
    })
    return s
  }, [hoverId, visibleEdges])

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
      layerEdges, layers.attack, entryIds, targetIds, sel, focus])

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
            <MiniMap pannable zoomable maskColor="rgba(245,246,250,.7)"
              nodeColor={(n) => styleOf((n.data as CircleData).e.entity_type).color} />
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
          </div>
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
                  title={available[k] ? '' : 'Backend endpoint not available yet'}
                  className={`flex items-center gap-2 rounded-2xl px-3.5 py-1.5 text-xs font-medium transition ${
                    on ? 'text-white' : available[k] ? 'text-slate-600 hover:bg-slate-900/5' : 'cursor-not-allowed text-slate-300'}`}
                  style={on ? { background: LAYER[k].color, boxShadow: `0 6px 16px -4px ${LAYER[k].color}99` } : undefined}>
                  {LAYER[k].label}
                  <span className={`rounded-full px-1.5 text-[10px] ${on ? 'bg-white/25' : 'bg-slate-900/5 text-slate-500'}`}>
                    {available[k] ? counts[k] : 'soon'}
                  </span>
                </button>
              )
            })}
          </div>
          <div className={`${card} pointer-events-auto flex p-1.5`}>
            {(['overlay', 'focus'] as const).map((v) => (
              <button key={v} onClick={() => setView(v)}
                className={`rounded-2xl px-3.5 py-1.5 text-xs font-medium transition ${view === v ? 'bg-slate-900 text-white shadow' : 'text-slate-600 hover:bg-slate-900/5'}`}>
                {v === 'overlay' ? 'Whole map' : 'Focus layer'}
              </button>
            ))}
          </div>
          <label className={`${card} pointer-events-auto flex cursor-pointer items-center gap-2 px-3.5 py-2.5 text-xs text-slate-600`}>
            <input type="checkbox" checked={showStructure} onChange={(e) => setShowStructure(e.target.checked)} />
            policies &amp; groups
          </label>
        </div>

        {/* right column */}
        <div className="absolute bottom-44 right-4 top-4 flex w-80 flex-col items-end gap-3">
          {graph && (
            <div className={`${card} pointer-events-auto flex items-center gap-3 px-3.5 py-2 text-[11px] text-slate-600`}>
              <span>version <code className="text-slate-800">{graph.graph_version}</code></span>
              <Chip>{graph.data_mode}</Chip>
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
          {inspector && <div key={sel?.kind + (sel?.id ?? '')} className={`${card} pointer-events-auto min-h-0 w-full overflow-auto p-4`}>{inspector}</div>}
        </div>

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
