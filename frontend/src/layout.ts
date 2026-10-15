import {
  forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY,
  type SimulationLinkDatum, type SimulationNodeDatum,
} from 'd3-force'

export interface LayoutNode { id: string; r: number }
export interface LayoutLink { source: string; target: string; weak: boolean }

type N = SimulationNodeDatum & LayoutNode
type L = SimulationLinkDatum<N> & { weak: boolean }

// Seeded so the same graph always gets the same picture.
function lcg(seed = 7) {
  let s = seed
  return () => (s = (s * 1664525 + 1013904223) % 4294967296) / 4294967296
}

export function layout(nodes: LayoutNode[], links: LayoutLink[]) {
  const ns: N[] = nodes.map((n) => ({ ...n }))
  const ls: L[] = links.map((l) => ({ source: l.source, target: l.target, weak: l.weak }))
  const sim = forceSimulation<N>(ns)
    .randomSource(lcg())
    .force('link', forceLink<N, L>(ls).id((d) => d.id)
      .distance((l) => (l.weak ? 150 : 95))
      .strength((l) => (l.weak ? 0.05 : 0.5)))
    .force('charge', forceManyBody<N>().strength(-320).distanceMax(500))
    .force('collide', forceCollide<N>().radius((d) => d.r + 22))
    .force('x', forceX<N>(0).strength(0.04))
    .force('y', forceY<N>(0).strength(0.04))
    .stop()
  for (let i = 0; i < 400; i++) sim.tick()
  const pos: Record<string, { x: number; y: number }> = {}
  ns.forEach((n) => { pos[n.id] = { x: n.x ?? 0, y: n.y ?? 0 } })
  return pos
}