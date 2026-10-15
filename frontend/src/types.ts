// Shapes returned by the HardCoded API (backend/api). Only what the UI reads.

export type Feasibility = 'feasible_under_model' | 'conditional' | 'blocked'

export interface GraphNode {
  entity_id: string
  entity_type: string
  identity_class: string
  name: string
  criticality?: string | null
  account_id?: string | null
}

export interface GraphEdge {
  edge_id: string
  source_id: string
  target_id: string
  relation_type: string
  status: string
  conditions: Record<string, unknown>
  evidence_ids: string[]
}

export interface GraphResponse {
  scenario_id: string
  graph_version: string
  data_mode: string
  warnings: string[]
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface AttackPath {
  path_id: string
  entry_node_id: string
  target_node_id: string
  node_ids: string[]
  edge_ids: string[]
  feasibility: Feasibility
  explanations: string[]
  // Relative route score from 0 to 1. NOT a probability. null means unknown.
  likelihood_score: number | null
  impact_score: number | null
  risk_score: number | null
  confidence: string
  score_reasons: string[]
  score_unknowns: string[]
}

export interface PathsResponse {
  scenario_id: string
  search: { truncated: boolean; truncation_reason: string | null; paths_found: number }
  assumptions: string[]
  paths: AttackPath[]
}

export interface ScenarioSummary {
  scenario_id: string
  title: string
}

export interface Fix {
  id: string
  label: string
  edge_ids: string[]
  status: string
  note: string
}

export interface Overlay {
  id: string
  label: string
  edge_ids: string[]
  node_ids?: string[]
  status: string
  note: string
}

export interface OverlaysResponse {
  warnings?: string[]
  search_truncated?: boolean
  access_requirements_loaded?: boolean
  summary?: { fixes: number; risk_before: number; risk_after: number; paths_left: number } | null
  fixes: Fix[]
  backup_routes?: Overlay[]
  access_lost?: Overlay[]
}
