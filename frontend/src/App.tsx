import { useEffect, useMemo, useState } from 'react'
import { getGraph, getOverlays, getPaths, getScenarios } from './api'
import GraphView from './GraphView'
import Inspector from './Inspector'
import { TYPE_STYLE } from './style'
import { buildModel, compromisedFrom } from './model'
import type { Model } from './model'
import type { AttackPath, GraphResponse, PathsResponse, ScenarioSummary } from './types'

type Mode = 'whole' | 'attack'
interface Loaded { graph: GraphResponse; paths: PathsResponse; model: Model }

export default function App() {
  const [scenarios, setScenarios] = useState<ScenarioSummary[]>([])
  const [scenarioId, setScenarioId] = useState<string | null>(null)
  const [data, setData] = useState<Loaded | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)
  const [mode, setMode] = useState<Mode>('attack')
  const [showAllEdges, setShowAllEdges] = useState(true)
  const [showReroute, setShowReroute] = useState(false)
  const [search, setSearch] = useState('')
  const [attacker, setAttacker] = useState<string | null>(null)
  const [selNode, setSelNode] = useState<string | null>(null)
  const [selEdge, setSelEdge] = useState<string | null>(null)
  const [selFix, setSelFix] = useState<string | null>(null)

  useEffect(() => {
    getScenarios()
      .then((s) => {
        setScenarios(s)
        setScenarioId((cur) => cur ?? s.find((x) => x.scenario_id.startsWith('scenario_08'))?.scenario_id ?? s[0]?.scenario_id ?? null)
      })
      .catch((e: Error) => setError(`Cannot reach the API at localhost:8000 (${e.message}). Start it with: python -m uvicorn backend.api.main:app --port 8000`))
  }, [reload])

  useEffect(() => {
    if (!scenarioId) return
    let cancelled = false
    Promise.all([getGraph(scenarioId), getPaths(scenarioId), getOverlays(scenarioId)])
      .then(([graph, paths, overlays]) => {
        if (cancelled) return
        setData({ graph, paths, model: buildModel(graph, paths, overlays) })
        setError(null)
        setAttacker(null); setSelNode(null); setSelEdge(null); setSelFix(null); setSearch('')
      })
      .catch((e: Error) => { if (!cancelled) setError(`Could not load ${scenarioId}: ${e.message}`) })
    return () => { cancelled = true }
  }, [scenarioId, reload])

  const model = data?.model ?? null
  const compromised = useMemo(
    () => new Set(model && attacker ? compromisedFrom(model, attacker).map((c) => c.node.entity_id) : []),
    [model, attacker],
  )

  // Edges the selected fix would cut (FIX style). Must stay above the early return: it is a hook.
  const cutEdges = useMemo(() => {
    const fix = model?.fixes.find((f) => f.id === selFix)
    return fix ? new Set(fix.edge_ids) : undefined
  }, [model, selFix])

  const focus = useMemo(() => {
    if (!model) return { nodes: null, edges: null }
    let paths: AttackPath[] | null = null
    if (selEdge) paths = model.pathsByEdge.get(selEdge) ?? []
    else if (attacker) paths = model.pathsByEntry.get(attacker) ?? []
    else if (selNode) paths = model.pathsByNode.get(selNode) ?? null
    if (paths === null) return { nodes: null, edges: null }
    const nodes = new Set<string>(paths.flatMap((p) => p.node_ids))
    const edges = new Set<string>(paths.flatMap((p) => p.edge_ids))
    if (selNode) nodes.add(selNode)
    if (selEdge) {
      edges.add(selEdge)
      const e = model.edgeById.get(selEdge)
      if (e) { nodes.add(e.source_id); nodes.add(e.target_id) }
    }
    return { nodes, edges }
  }, [model, attacker, selNode, selEdge])

  if (!data || !model || !scenarioId) {
    return (
      <div className="boot">
        {error ? (
          <>
            <p className="warn">{error}</p>
            <button className="btn" onClick={() => setReload((x) => x + 1)}>Retry</button>
          </>
        ) : <p>Loading…</p>}
      </div>
    )
  }

  const attackNodeIds = new Set(model.attackPaths.flatMap((p) => p.node_ids))
  const attackEdges = data.graph.edges.filter((e) => model.attackEdgeIds.has(e.edge_id))

  // BACKUP_ROUTE edges (rerouting). Only drawn when the toggle is on, and kept separate from attack edges.
  const backupIds = showReroute ? new Set(model.backups.flatMap((b) => b.edge_ids)) : new Set<string>()
  const backupEdges = data.graph.edges.filter((e) => backupIds.has(e.edge_id))
  const backupNodes = new Set(backupEdges.flatMap((e) => [e.source_id, e.target_id]))

  const visibleNodes = mode === 'whole' ? data.graph.nodes
    : data.graph.nodes.filter((n) => attackNodeIds.has(n.entity_id) || backupNodes.has(n.entity_id))
  const layoutEdges = mode === 'whole' ? data.graph.edges : [...attackEdges, ...backupEdges]
  const drawnEdges = mode === 'whole' && showAllEdges ? data.graph.edges
    : [...attackEdges, ...backupEdges.filter((e) => !model.attackEdgeIds.has(e.edge_id))]

  function clickNode(id: string) {
    if (!model) return
    setSelEdge(null); setSelFix(null)
    if (attacker && compromised.has(id)) { setSelNode(id); return }
    if (model.attackNodeIds.has(id)) { setAttacker(id); setSelNode(id); return }
    setSelNode(id)
    setAttacker(null)
  }
  function clickEdge(id: string) { setSelEdge(id); setSelNode(null); setAttacker(null); setSelFix(null) }
  function clearAll() { setSelEdge(null); setSelNode(null); setAttacker(null); setSelFix(null) }
  function firstMatch() {
    const q = search.trim().toLowerCase()
    const hit = visibleNodes.find((n) => q && n.name.toLowerCase().includes(q))
    if (hit) clickNode(hit.entity_id)
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">HardCoded <span>NHI attack paths</span></div>
        <select value={scenarioId} onChange={(e) => setScenarioId(e.target.value)} aria-label="Scenario">
          {scenarios.map((s) => <option key={s.scenario_id} value={s.scenario_id}>{s.title}</option>)}
        </select>
        <div className="seg" role="group" aria-label="View">
          <button className={mode === 'whole' ? 'on' : ''} onClick={() => { setMode('whole'); clearAll() }}>Whole map</button>
          <button className={mode === 'attack' ? 'on' : ''} onClick={() => { setMode('attack'); clearAll() }}>Attack paths</button>
        </div>
        <input className="search" placeholder="Search nodes" value={search}
          onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && firstMatch()} />
        {mode === 'whole' && (
          <label className="check">
            <input type="checkbox" checked={showAllEdges} onChange={(e) => setShowAllEdges(e.target.checked)} /> All edges
          </label>
        )}
        <label className="check" title={model.backups.length === 0 ? 'No verified backup routes for this scenario' : undefined}>
          <input type="checkbox" checked={showReroute} disabled={model.backups.length === 0}
            onChange={(e) => setShowReroute(e.target.checked)} /> Show rerouting
        </label>
        <span className="spacer" />
        <span className="chip">Test data</span>
        <span className="chip">Simulation only</span>
        {data.paths.search.truncated && <span className="chip warn">Search truncated</span>}
      </header>
      <main className="main">
        <div className="stage">
          <GraphView
            key={`${scenarioId}|${mode}|${showReroute}`}
            nodes={visibleNodes} layoutEdges={layoutEdges} edges={drawnEdges} model={model}
            selectedNodeId={selNode} selectedEdgeId={selEdge} attackerId={attacker}
            focusNodes={focus.nodes} focusEdges={focus.edges} compromised={compromised} search={search}
            cutEdges={cutEdges} backupEdges={showReroute ? backupIds : undefined}
            onNode={clickNode} onEdge={clickEdge} onBackground={clearAll}
          />
          <div className="legend">
            {Object.values(TYPE_STYLE).map((t) => (
              <span key={t.label}><i className="dot" style={{ background: t.color }}>{t.glyph}</i>{t.label}</span>
            ))}
            <span><i className="ring red" />Attack node</span>
            <span><i className="ring dark" />Target</span>
            <span><i className="line red" />Attack arrow</span>
            <span><i className="line red dashed" />Conditional</span>
            <span><i className="line gray" />Other relationship</span>
            <span><b style={{ color: '#059669' }}>✕</b> Fix cut</span>
            <span><b style={{ color: '#0284c7' }}>→</b> Backup route</span>
          </div>
        </div>
        <Inspector
          model={model} paths={data.paths} warnings={data.graph.warnings}
          selEdge={selEdge} selNode={selNode} attacker={attacker}
          selFix={selFix} onFix={setSelFix}
          onNode={clickNode} onBack={() => attacker && (setSelNode(attacker))}
        />
      </main>
    </div>
  )
}