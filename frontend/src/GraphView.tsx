import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { PointerEvent as RPointerEvent } from 'react'
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from 'd3-force'
import type { SimulationLinkDatum, SimulationNodeDatum } from 'd3-force'
import type { Model } from './model'
import { relLabel } from './model'
import { styleOf } from './style'
import type { GraphEdge, GraphNode } from './types'

const R = 20
const RED = '#dc2626'
const GRAY = '#94a3b8'
const GREEN = '#059669'
const BLUE = '#0284c7'

interface Pt { x: number; y: number }
interface View { x: number; y: number; k: number }
interface SimNode extends SimulationNodeDatum { id: string }

/** Deterministic force layout, settled up front so the map never jitters. */
function layout(nodes: GraphNode[], edges: GraphEdge[]): Map<string, Pt> {
  const sims: SimNode[] = nodes.map((n, i) => ({
    id: n.entity_id, x: Math.cos(i * 2.4) * (40 + i * 9), y: Math.sin(i * 2.4) * (40 + i * 9),
  }))
  const ids = new Set(sims.map((s) => s.id))
  const seen = new Set<string>()
  const links: SimulationLinkDatum<SimNode>[] = []
  for (const e of edges) {
    const key = [e.source_id, e.target_id].sort().join('|')
    if (!ids.has(e.source_id) || !ids.has(e.target_id) || e.source_id === e.target_id || seen.has(key)) continue
    seen.add(key)
    links.push({ source: e.source_id, target: e.target_id })
  }
  const sim = forceSimulation(sims)
    .force('link', forceLink<SimNode, SimulationLinkDatum<SimNode>>(links).id((d) => d.id).distance(130).strength(0.2))
    .force('charge', forceManyBody().strength(-520))
    .force('collide', forceCollide(54))
    .force('x', forceX(0).strength(0.04))
    .force('y', forceY(0).strength(0.04))
    .stop()
  for (let i = 0; i < 400; i++) sim.tick()
  return new Map(sims.map((s) => [s.id, { x: s.x ?? 0, y: s.y ?? 0 }]))
}

function curve(a: Pt, b: Pt, off: number) {
  const dx = b.x - a.x
  const dy = b.y - a.y
  const len = Math.hypot(dx, dy) || 1
  const cx = (a.x + b.x) / 2 + (-dy / len) * off * 2
  const cy = (a.y + b.y) / 2 + (dx / len) * off * 2
  const unit = (x: number, y: number) => {
    const l = Math.hypot(x, y) || 1
    return { x: x / l, y: y / l }
  }
  const s = unit(cx - a.x, cy - a.y)
  const t = unit(cx - b.x, cy - b.y)
  const x1 = a.x + s.x * R
  const y1 = a.y + s.y * R
  const x2 = b.x + t.x * (R + 5)
  const y2 = b.y + t.y * (R + 5)
  return { d: `M${x1},${y1} Q${cx},${cy} ${x2},${y2}`, lx: (x1 + 2 * cx + x2) / 4, ly: (y1 + 2 * cy + y2) / 4 }
}

interface Props {
  backupEdges?: Set<string>
  nodes: GraphNode[]
  layoutEdges: GraphEdge[]   // edges that shape the layout
  edges: GraphEdge[]         // edges that are drawn
  model: Model
  selectedNodeId: string | null
  selectedEdgeId: string | null
  focusNodes: Set<string> | null
  focusEdges: Set<string> | null
  compromised: Set<string>
  cutEdges?: Set<string>     // edges the selected fix would cut (FIX style, never attack style)
  attackerId: string | null
  search: string
  onNode: (id: string) => void
  onEdge: (id: string) => void
  onBackground: () => void
}

type Drag =
  | { kind: 'pan'; sx: number; sy: number; ox: number; oy: number; moved: boolean }
  | { kind: 'node'; id: string; sx: number; sy: number; ox: number; oy: number; moved: boolean }

export default function GraphView(p: Props) {
  const { nodes, edges, model } = p
  const [pos, setPos] = useState(() => layout(nodes, p.layoutEdges))
  const [view, setView] = useState<View>({ x: 0, y: 0, k: 1 })
  const svgRef = useRef<SVGSVGElement>(null)
  const drag = useRef<Drag | null>(null)
  const viewRef = useRef(view)
  useEffect(() => { viewRef.current = view }, [view])

  const fit = (map: Map<string, Pt> = pos) => {
    const el = svgRef.current
    if (!el || map.size === 0) return
    const xs = [...map.values()].map((q) => q.x)
    const ys = [...map.values()].map((q) => q.y)
    const pad = 80
    const bw = Math.max(...xs) - Math.min(...xs) + pad * 2
    const bh = Math.max(...ys) - Math.min(...ys) + pad * 2
    const k = Math.min(el.clientWidth / bw, el.clientHeight / bh, 1.3)
    setView({
      k,
      x: el.clientWidth / 2 - ((Math.max(...xs) + Math.min(...xs)) / 2) * k,
      y: el.clientHeight / 2 - ((Math.max(...ys) + Math.min(...ys)) / 2) * k,
    })
  }
  useLayoutEffect(() => { fit() }, [])  // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const el = svgRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const r = el.getBoundingClientRect()
      const px = e.clientX - r.left
      const py = e.clientY - r.top
      setView((v) => {
        const k = Math.min(3, Math.max(0.15, v.k * Math.exp(-e.deltaY * 0.0015)))
        const f = k / v.k
        return { k, x: px - (px - v.x) * f, y: py - (py - v.y) * f }
      })
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [])

  const zoomBy = (f: number) => {
    const el = svgRef.current
    if (!el) return
    const px = el.clientWidth / 2
    const py = el.clientHeight / 2
    setView((v) => {
      const k = Math.min(3, Math.max(0.15, v.k * f))
      const g = k / v.k
      return { k, x: px - (px - v.x) * g, y: py - (py - v.y) * g }
    })
  }

  function down(e: RPointerEvent<SVGSVGElement>) {
    const nodeEl = (e.target as Element).closest('[data-node]')
    const edgeEl = (e.target as Element).closest('[data-edge]')
    if (edgeEl) return  // edge clicks are plain click events
    svgRef.current?.setPointerCapture(e.pointerId)
    if (nodeEl) {
      const id = nodeEl.getAttribute('data-node') as string
      const q = pos.get(id)
      if (!q) return
      drag.current = { kind: 'node', id, sx: e.clientX, sy: e.clientY, ox: q.x, oy: q.y, moved: false }
    } else {
      drag.current = { kind: 'pan', sx: e.clientX, sy: e.clientY, ox: view.x, oy: view.y, moved: false }
    }
  }
  function move(e: RPointerEvent<SVGSVGElement>) {
    const d = drag.current
    if (!d) return
    const dx = e.clientX - d.sx
    const dy = e.clientY - d.sy
    if (!d.moved && Math.hypot(dx, dy) < 4) return
    d.moved = true
    if (d.kind === 'pan') setView((v) => ({ ...v, x: d.ox + dx, y: d.oy + dy }))
    else {
      const k = viewRef.current.k
      setPos((m) => new Map(m).set(d.id, { x: d.ox + dx / k, y: d.oy + dy / k }))
    }
  }
  function up() {
    const d = drag.current
    drag.current = null
    if (!d || d.moved) return
    if (d.kind === 'node') p.onNode(d.id)
    else p.onBackground()
  }

  // Parallel and reverse edges between the same pair fan out so every arrow stays clickable.
  const groups = new Map<string, GraphEdge[]>()
  for (const e of edges) {
    const key = [e.source_id, e.target_id].sort().join('|')
    groups.set(key, [...(groups.get(key) ?? []), e])
  }
  const q = p.search.trim().toLowerCase()
  const dimNode = (n: GraphNode) =>
    (p.focusNodes !== null && !p.focusNodes.has(n.entity_id)) || (q !== '' && !n.name.toLowerCase().includes(q))

  const drawn = edges.flatMap((e) => {
    const a = pos.get(e.source_id)
    const b = pos.get(e.target_id)
    if (!a || !b || e.source_id === e.target_id) return []
    const group = groups.get([e.source_id, e.target_id].sort().join('|')) ?? [e]
    const i = group.indexOf(e)
    const canonical = [e.source_id, e.target_id].sort()[0] === e.source_id
    const off = (i - (group.length - 1) / 2) * 30 * (canonical ? 1 : -1)
    const paths = model.pathsByEdge.get(e.edge_id) ?? []
    return [{ e, g: curve(a, b, off), attack: paths.length > 0, conditionalOnly: paths.every((x) => x.feasibility === 'conditional') }]
  })
      const isCutEdge = (id: string) => p.cutEdges?.has(id) ?? false
  const isBackup = (id: string) => !isCutEdge(id) && (p.backupEdges?.has(id) ?? false)
  const ordered = [
    ...drawn.filter((x) => !x.attack && !isBackup(x.e.edge_id) && !isCutEdge(x.e.edge_id)),
    ...drawn.filter((x) => x.attack && !isBackup(x.e.edge_id) && !isCutEdge(x.e.edge_id)),
    ...drawn.filter((x) => isBackup(x.e.edge_id)),
    ...drawn.filter((x) => isCutEdge(x.e.edge_id)),
  ]

  return (
    <div className="canvas">
      <svg ref={svgRef} className="graph" onPointerDown={down} onPointerMove={move} onPointerUp={up}>
        <defs>
          {[['blue', BLUE],['gray', GRAY], ['red', RED], ['dark', '#0f172a'], ['green', GREEN]].map(([id, c]) => (
            <marker key={id} id={`arrow-${id}`} viewBox="0 0 12 12" refX="10" refY="6" markerWidth="11" markerHeight="11"
              markerUnits="userSpaceOnUse" orient="auto">
              <path d="M0,1 L11,6 L0,11 z" fill={c} />
            </marker>
          ))}
        </defs>
        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
                    {ordered.map(({ e, g, attack, conditionalOnly }) => {
            
            const selected = e.edge_id === p.selectedEdgeId
            const cut = isCutEdge(e.edge_id)
            
                        const backup = isBackup(e.edge_id)
            const inFocus = cut || backup || (p.focusEdges ? p.focusEdges.has(e.edge_id) : true)
            const color = cut ? GREEN : selected ? '#0f172a' : attack ? RED : backup ? BLUE : GRAY
            const opacity = !inFocus ? 0.06 : cut || attack || backup ? 1 : p.focusEdges ? 1 : 0.35
            const showLabel = cut || backup || selected || (p.focusEdges !== null && inFocus && attack)
            return (
              <g key={e.edge_id} data-edge={e.edge_id} opacity={opacity} style={{ cursor: 'pointer' }}
                onClick={() => p.onEdge(e.edge_id)}>
                {(selected || cut) && (
                  <path d={g.d} fill="none" stroke={cut ? '#6ee7b7' : '#fca5a5'} strokeWidth={9} strokeLinecap="round" opacity={0.6} />
                )}
                <path d={g.d} fill="none" stroke="transparent" strokeWidth={14} />
                <path d={g.d} fill="none" stroke={color} strokeWidth={cut ? 3.2 : attack ? 2.6 : 1.1}
                  strokeDasharray={cut ? '8 6' : attack && conditionalOnly ? '7 5' : e.relation_type === 'has_policy' && !attack && !backup ? '2 4' : undefined}
                  markerEnd={'url(#arrow-${cut ? ‘green’ : selected ? ‘dark’ : attack ? ‘red’ : backup ? ‘blue’ : ‘gray’})'} />
                {cut && (
                  <g transform={`translate(${g.lx},${g.ly})`}>
                    <circle r={9} fill="#fff" stroke={GREEN} strokeWidth={2} />
                    <text className="badge" textAnchor="middle" dy="0.35em" fill={GREEN}>✕</text>
                  </g>
                )}
                {showLabel && (
                  <text x={g.lx} y={g.ly - (cut ? 14 : 5)} className="edge-label" textAnchor="middle">
                    {cut ? 'cut by fix' : backup ? 'backup route' : relLabel(e.relation_type)}
                  </text>
                )}
                <title>${backup ? 'BACKUP ROUTE ' : ''}{`${cut ? 'FIX cuts ' : ''}${relLabel(e.relation_type)}: ${model.nodeById.get(e.source_id)?.name} → ${model.nodeById.get(e.target_id)?.name}`}</title>
              </g>
            )
          })}
          {nodes.map((n) => {
            const pt = pos.get(n.entity_id)
            if (!pt) return null
            const st = styleOf(n.entity_type)
            const isAttacker = model.attackNodeIds.has(n.entity_id)
            const isTarget = model.targetIds.has(n.entity_id)
            const isSel = n.entity_id === p.selectedNodeId
            const isComp = p.compromised.has(n.entity_id)
            return (
              <g key={n.entity_id} data-node={n.entity_id} transform={`translate(${pt.x},${pt.y})`}
                opacity={dimNode(n) ? 0.16 : 1} style={{ cursor: 'pointer' }}>
                {isSel && <circle r={R + 10} fill="none" stroke="#0f172a" strokeWidth={2.5} />}
                {isComp && !isSel && <circle r={R + 8} fill="#fed7aa" opacity={0.85} />}
                {isAttacker && <circle r={R + 5} fill="none" stroke={RED} strokeWidth={3} />}
                {isTarget && !isAttacker && <circle r={R + 5} fill="none" stroke="#7f1d1d" strokeWidth={3} strokeDasharray="3 3" />}
                <circle r={R} fill={st.color} stroke="#fff" strokeWidth={2} />
                <text className="glyph" textAnchor="middle" dy="0.35em">{st.glyph}</text>
                {isAttacker && (
                  <g transform={`translate(${R - 2},${-R + 2})`}>
                    <circle r={8} fill={RED} stroke="#fff" strokeWidth={1.5} />
                    <text className="badge" textAnchor="middle" dy="0.35em">!</text>
                  </g>
                )}
                {isTarget && (
                  <g transform={`translate(${R - 2},${R - 2})`}>
                    <circle r={8} fill="#7f1d1d" stroke="#fff" strokeWidth={1.5} />
                    <text className="badge" textAnchor="middle" dy="0.35em">T</text>
                  </g>
                )}
                <text className="caption" textAnchor="middle" y={R + 20}>
                  {n.name.length > 24 ? n.name.slice(0, 23) + '…' : n.name}
                </text>
                <title>{`${st.label}: ${n.name}${p.attackerId === n.entity_id ? ' (selected attack node)' : ''}`}</title>
              </g>
            )
          })}
        </g>
      </svg>
      {nodes.length === 0 && <div className="empty">Nothing to show here. Try the Whole map view.</div>}
      <div className="zoom">
        <button onClick={() => zoomBy(1.25)} aria-label="Zoom in">+</button>
        <button onClick={() => zoomBy(0.8)} aria-label="Zoom out">−</button>
        <button onClick={() => fit()} aria-label="Fit to screen">Fit</button>
      </div>
    </div>
  )
}
