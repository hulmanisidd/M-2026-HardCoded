# Data requirements for a REAL (non-synthetic) model

Target: y = 1 if an attacker starting at `entry_node_id`, within a fixed window
(decide it first, e.g. 30 days), successfully reaches `target_node_id` using
this exact path; y = 0 if the path existed and was not exploited.

One row per (path, graph_version, outcome). Required columns:
`path_id`, `graph_version`, `outcome` (0/1), `outcome_source`
(incident / red_team / simulation), `observed_window_start/end`.
Plus the graph snapshot the path was discovered on, so features can be recomputed.

Cautions: paths that were never tested are NOT negatives (selection bias);
red-team outcomes reflect the red team, not real attackers; keep train/test
splits grouped by account or snapshot to avoid leakage.