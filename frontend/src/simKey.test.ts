import { describe, expect, it } from 'vitest'
import { resultMatches } from './simKey'

const all = ['fix_a', 'fix_b', 'fix_c', 'fix_d']

describe('resultMatches (stale simulation results)', () => {
  it('is current when the selection equals what was simulated, in any order', () => {
    expect(resultMatches(['fix_a', 'fix_b', 'fix_c'], ['fix_c', 'fix_a', 'fix_b'])).toBe(true)
  })
  it('is stale after going from 4 to 3 selected', () => {
    expect(resultMatches(all, ['fix_a', 'fix_b', 'fix_c'])).toBe(false)
  })
  it('is stale after going from 3 to 2 selected (the reported bug)', () => {
    expect(resultMatches(['fix_a', 'fix_b', 'fix_c'], ['fix_a', 'fix_b'])).toBe(false)
  })
  it('is stale after going from 2 to 0 selected', () => {
    expect(resultMatches(['fix_a', 'fix_b'], [])).toBe(false)
  })
  it('is stale when a different fix replaces one with the same count', () => {
    expect(resultMatches(['fix_a', 'fix_b'], ['fix_a', 'fix_c'])).toBe(false)
  })
  it('is current again if the selection returns to the simulated set', () => {
    expect(resultMatches(['fix_a', 'fix_b'], ['fix_b', 'fix_a'])).toBe(true)
  })
})
