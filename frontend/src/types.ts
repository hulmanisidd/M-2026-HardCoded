export type Feasibility = 'feasible_under_model' | 'conditional' | 'blocked'

export interface GraphNode {
  entity_id: string
  entity_type: string
  identity_class: string
  name: string
  criticality?: string | null
  account_id?: string | null
  attributes: Record<string, unknown>
}

export interface GraphEdge {
  edge_id: string
  source_id: string
  target_id: string
  relation_type: string
  family: 'authorization' | 'context' | 'structure'
  status: string
  conditions: Record<string, unknown>
  evidence_ids: string[]
}

export interface GraphResponse {
  scenario_id: string
  graph_version: string
  observed_at: string
  data_mode: string
  warnings: string[]
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface AttackPath {
  path_id: string
  graph_version: string
  entry_node_id: string
  target_node_id: string
  node_ids: string[]
  edge_ids: string[]
  feasibility: Feasibility
  evidence_ids: string[]
  explanations: string[]
}

export interface PathsResponse {
  scenario_id: string
  graph_version: string
  search: {
    max_depth: number
    max_paths: number
    truncated: boolean
    truncation_reason: string | null
    paths_found: number
    unknown_entry_ids: string[]
    unknown_target_ids: string[]
  }
  assumptions: string[]
  paths: AttackPath[]
}

export interface ScenarioSummary {
  scenario_id: string
  title: string
  data_mode: string
  has_access_requirements: boolean
}

// Proposed contract (review with Person 2 before locking).
// access_lost entries have no edges; they point at the two nodes via node_ids.
export interface Overlay {
  id: string
  label: string
  edge_ids: string[]
  node_ids?: string[]
  status: string
  note: string
}

export interface OverlaysResponse {
  scenario_id?: string
  graph_version?: string
  mode?: string
  applied_to_cloud?: boolean
  search_truncated?: boolean
  access_requirements_loaded?: boolean
  warnings?: string[]
  summary?: { fixes: number; risk_before: number; risk_after: number; paths_left: number } | null
  fixes: Overlay[]
  backup_routes: Overlay[]
  access_lost: Overlay[]
}