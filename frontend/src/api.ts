import type { GraphResponse, OverlaysResponse, PathsResponse, ScenarioSummary, SimulationResponse } from './types'

const API = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

async function get<T>(url: string): Promise<T> {
  const r = await fetch(`${API}${url}`)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json() as Promise<T>
}

export const getScenarios = () => get<ScenarioSummary[]>('/api/scenarios')
export const getGraph = (id: string) => get<GraphResponse>(`/api/scenarios/${id}/graph`)
export const getPaths = (id: string) => get<PathsResponse>(`/api/scenarios/${id}/paths`)

// Fixes are optional: if this fails the UI says remediation is unavailable instead of breaking.
export async function getOverlays(id: string): Promise<OverlaysResponse | null> {
  try {
    return await get<OverlaysResponse>(`/api/scenarios/${id}/overlays`)
  } catch {
    return null
  }
}

// fixIds omitted = simulate every proposed fix. Simulation only: nothing is applied to AWS.
export async function simulateFixes(id: string, fixIds?: string[]): Promise<SimulationResponse> {
  const r = await fetch(`${API}/api/scenarios/${id}/simulate-remediation`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ fix_ids: fixIds ?? null }),
  })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json() as Promise<SimulationResponse>
}

