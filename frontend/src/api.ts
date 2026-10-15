import type {
  GraphResponse, OverlaysResponse, PathsResponse, ScenarioSummary, SimulationResponse,
} from './types'

const API = 'http://localhost:8000'

async function get<T>(url: string): Promise<T> {
  const r = await fetch(`${API}${url}`)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json() as Promise<T>
}

export const getScenarios = () => get<ScenarioSummary[]>('/api/scenarios')
export const getGraph = (id: string) => get<GraphResponse>(`/api/scenarios/${id}/graph`)
export const getPaths = (id: string) => get<PathsResponse>(`/api/scenarios/${id}/paths`)

// A failure means "layer unavailable", not an error screen.
export async function getOverlays(id: string): Promise<OverlaysResponse | null> {
  try {
    return await get<OverlaysResponse>(`/api/scenarios/${id}/overlays`)
  } catch {
    return null
  }
}

// Simulation only: the API never applies anything to AWS. fixIds null = all proposed fixes.
export async function simulateRemediation(id: string, fixIds: string[] | null): Promise<SimulationResponse> {
  const r = await fetch(`${API}/api/scenarios/${id}/simulate-remediation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fix_ids: fixIds }),
  })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json() as Promise<SimulationResponse>
}