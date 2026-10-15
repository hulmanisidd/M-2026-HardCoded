/** Order-independent key for a set of fix ids. */
export const selectionKey = (ids: Iterable<string>): string => [...new Set(ids)].sort().join('\u0000')

/**
 * A simulation result may be shown as current only if it was computed for exactly the fixes
 * that are selected now. `simulatedIds` must come from the backend (fixes_simulated), not from UI state.
 */
export function resultMatches(simulatedIds: Iterable<string>, pickedIds: Iterable<string>): boolean {
  return selectionKey(simulatedIds) === selectionKey(pickedIds)
}
