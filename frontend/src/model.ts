import type { AttackPath, Fix,Overlay, GraphEdge, GraphNode, GraphResponse, OverlaysResponse, PathsResponse } from './types'

export interface Model {
  nodeById: Map<string, GraphNode>
  edgeById: Map<string, GraphEdge>
  attackPaths: AttackPath[]          // feasible or conditional (blocked paths are not attacks)
  blockedCount: number
  pathsByEdge: Map<string, AttackPath[]>
  pathsByEntry: Map<string, AttackPath[]>
  pathsByNode: Map<string, AttackPath[]>
  attackNodeIds: Set<string>         // entry points of at least one attack path
  targetIds: Set<string>             // end of at least one attack path
  attackEdgeIds: Set<string>
  policiesOf: Map<string, string[]>  // node -> attached policy names
  fixes: Fix[]
  fixesAvailable: boolean
  backups: Overlay[]
  accessLost: Overlay[]
  overlayWarnings: string[]
  summary: OverlaysResponse['summary']
}

function push<K, V>(m: Map<K, V[]>, k: K, v: V) {
  const a = m.get(k)
  if (a) a.push(v)
  else m.set(k, [v])
}

export function buildModel(g: GraphResponse, p: PathsResponse, o: OverlaysResponse | null): Model {
  const nodeById = new Map(g.nodes.map((n) => [n.entity_id, n]))
  const edgeById = new Map(g.edges.map((e) => [e.edge_id, e]))
  const attackPaths = p.paths.filter((x) => x.feasibility !== 'blocked')
  const pathsByEdge = new Map<string, AttackPath[]>()
  const pathsByEntry = new Map<string, AttackPath[]>()
  const pathsByNode = new Map<string, AttackPath[]>()
  const targetIds = new Set<string>()
  for (const ap of attackPaths) {
    push(pathsByEntry, ap.entry_node_id, ap)
    targetIds.add(ap.target_node_id)
    for (const e of ap.edge_ids) push(pathsByEdge, e, ap)
    for (const n of new Set(ap.node_ids)) push(pathsByNode, n, ap)
  }
  const policiesOf = new Map<string, string[]>()
  for (const e of g.edges) {
    if (e.relation_type !== 'has_policy') continue
    const name = nodeById.get(e.target_id)?.name
    if (name) push(policiesOf, e.source_id, name)
  }
  return {
    nodeById, edgeById, attackPaths, blockedCount: p.paths.length - attackPaths.length,
    pathsByEdge, pathsByEntry, pathsByNode,
    attackNodeIds: new Set(pathsByEntry.keys()), targetIds,
    attackEdgeIds: new Set(pathsByEdge.keys()), policiesOf,
    fixes: o?.fixes ?? [], fixesAvailable: o !== null,
        backups: o?.backup_routes ?? [], accessLost: o?.access_lost ?? [],
    overlayWarnings: o?.warnings ?? [], summary: o?.summary ?? null,
    
  }
  
}

export const nameOf = (m: Model, id: string) => m.nodeById.get(id)?.name ?? id.split('/').pop() ?? id

export interface Compromised {
  node: GraphNode
  isTarget: boolean
  routes: AttackPath[]
}

/** Every node an attacker can reach through attack paths (the attacker itself excluded). */
export function compromisedFrom(m: Model, attackerId: string): Compromised[] {
  const acc = new Map<string, Compromised>()
  for (const p of m.pathsByEntry.get(attackerId) ?? []) {
    for (const id of p.node_ids) {
      if (id === attackerId) continue
      const node = m.nodeById.get(id)
      if (!node) continue
      const row = acc.get(id) ?? { node, isTarget: false, routes: [] }
      row.routes.push(p)
      if (id === p.target_node_id) row.isTarget = true
      acc.set(id, row)
    }
  }
  return [...acc.values()].sort(
    (a, b) => Number(b.isTarget) - Number(a.isTarget) || (bestRisk(b.routes) ?? -1) - (bestRisk(a.routes) ?? -1)
      || a.node.name.localeCompare(b.node.name),
  )
}

/** Routes that pass through (or end at) a node, optionally limited to one attacker. */
export function routesThrough(m: Model, nodeId: string, attackerId: string | null): AttackPath[] {
  return (m.pathsByNode.get(nodeId) ?? []).filter(
    (p) => p.node_ids[0] !== nodeId && (!attackerId || p.entry_node_id === attackerId),
  )
}

export interface Remediation {
  routes: AttackPath[]
  rows: { fix: Fix; blocks: AttackPath[] }[]
  uncovered: AttackPath[]
}

/** Fixes that cut at least one route reaching the node. */
export function remediationFor(m: Model, nodeId: string, attackerId: string | null): Remediation {
  const routes = routesThrough(m, nodeId, attackerId)
  const rows = m.fixes
    .map((fix) => ({ fix, blocks: routes.filter((p) => p.edge_ids.some((e) => fix.edge_ids.includes(e))) }))
    .filter((r) => r.blocks.length > 0)
    .sort((a, b) => b.blocks.length - a.blocks.length)
  const covered = new Set(rows.flatMap((r) => r.blocks.map((p) => p.path_id)))
  return { routes, rows, uncovered: routes.filter((p) => !covered.has(p.path_id)) }
}

export const bestRisk = (paths: AttackPath[]): number | null => {
  const v = paths.map((p) => p.risk_score).filter((x): x is number => x !== null)
  return v.length ? Math.max(...v) : null
}
export const bestLikelihood = (paths: AttackPath[]): number | null => {
  const v = paths.map((p) => p.likelihood_score).filter((x): x is number => x !== null)
  return v.length ? Math.max(...v) : null
}

export const fmtScore = (x: number | null) => (x === null ? 'unknown' : x.toFixed(2))
export const relLabel = (r: string) => r.replace(/_/g, ' ')


export function backupsForFix(m: Model, fix: Fix): Overlay[] {
  return m.backups.filter(
    (backup) => !backup.edge_ids.some((id) => fix.edge_ids.includes(id)),
  )
}

export function lostForFix(m: Model, _fix: Fix): Overlay[] {
  return m.accessLost
}

export function routeText(route: Overlay): string {
  return route.label.replace(/^Backup \| /, '')
}