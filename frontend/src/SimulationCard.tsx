import { Component, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { getOverlays, simulateFixes } from './api'
import type { Fix, SimulationResponse, Verdict } from './types'

const TONE: Record<Verdict, { icon: string; cls: string }> = {
  GOOD: { icon: '✅', cls: 'v-good' },
  NEEDS_REVIEW: { icon: '⚠️', cls: 'v-review' },
  PARTIAL: { icon: '🟡', cls: 'v-partial' },
  INEFFECTIVE: { icon: '❌', cls: 'v-bad' },
  UNVERIFIED: { icon: '❔', cls: 'v-unknown' },
}

const SHOW = 5 // long lists (many routes or fixes) are collapsed so the card stays readable

function List({ title, items, cls }: { title: string; items: string[]; cls?: string }) {
  const [all, setAll] = useState(false)
  if (!Array.isArray(items) || items.length === 0) return null
  const shown = all ? items : items.slice(0, SHOW)
  return (
    <div className={`sim-block ${cls ?? ''}`}>
      <h4>{title} ({items.length})</h4>
      <ul>{shown.map((t, i) => <li key={i}>{t}</li>)}</ul>
      {items.length > SHOW && (
        <button className="linkbtn" onClick={() => setAll(!all)}>
          {all ? 'Show fewer' : `Show all ${items.length}`}
        </button>
      )}
    </div>
  )
}

function SimulationCardInner({ scenarioId }: { scenarioId: string }) {
  const [res, setRes] = useState<SimulationResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [tech, setTech] = useState(false)
  const [fixes, setFixes] = useState<Fix[]>([])
  const [picked, setPicked] = useState<Set<string>>(new Set())

  // Load the proposed fixes so the person can try them one by one. All start selected.
  useEffect(() => {
    let live = true
    getOverlays(scenarioId).then((o) => {
      if (!live || !o) return
      const fx = Array.isArray(o.fixes) ? o.fixes : []
      setFixes(fx)
      setPicked(new Set(fx.map((f) => f.id)))
    }).catch(() => {})
    return () => { live = false }
  }, [scenarioId])

  const toggle = (id: string) =>
    setPicked((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  const allPicked = fixes.length > 0 && picked.size === fixes.length

  const run = async () => {
    setBusy(true)
    setErr(null)
    try {
      setRes(await simulateFixes(scenarioId, allPicked || fixes.length === 0 ? undefined : [...picked]))
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Simulation failed')
    } finally {
      setBusy(false)
    }
  }

  const x = res?.explanation
  const tone = x ? (TONE[x.verdict] ?? TONE.UNVERIFIED) : null
  return (
    <section className="sim-card">
      <h3>What happens if we apply the proposed fixes?</h3>
      {fixes.length > 1 && (
        <fieldset className="sim-pick" style={{ maxHeight: 220, overflowY: 'auto' }}>
          <legend>Fixes to include ({picked.size} of {fixes.length})</legend>
          {fixes.map((f) => (
            <label key={f.id}>
              <input type="checkbox" checked={picked.has(f.id)} onChange={() => toggle(f.id)} /> {f.label}
            </label>
          ))}
        </fieldset>
      )}
      <button className="btn" onClick={run} disabled={busy || (fixes.length > 0 && picked.size === 0)}>
        {busy ? 'Simulating…' : allPicked || fixes.length <= 1 ? 'Run simulation' : `Simulate ${picked.size} selected fix${picked.size === 1 ? '' : 'es'}`}
      </button>
      {err && <p className="warn">Could not run the simulation: {err}</p>}
      {x && tone && res && (
        <>
          <div className={`sim-verdict ${tone.cls}`}>
            <span className="sim-icon">{tone.icon}</span>
            <div><b>{x.verdict_label}</b><p>{x.headline}</p></div>
          </div>
          <List title="Side effects on legitimate access" items={x.side_effects} cls="sim-warn" />
          <List title="Dangerous routes still open" items={x.still_open} cls="sim-warn" />
          <List title="Dangerous routes closed" items={x.blocked} />
          <List title="Access kept through a backup route" items={x.kept} />
          <List title="Limits of this analysis" items={x.cautions} cls="sim-note" />
          <List title="What to do next" items={x.next_steps} />
          {x.approval && <p className="note strong">{x.approval}</p>}
          <button className="linkbtn" onClick={() => setTech(!tech)}>
            {tech ? 'Hide technical details' : 'Show technical details'}
          </button>
          {tech && (
            <div className="sim-tech">
              <p className="note">Run {res.run_id}. Fixes simulated: {(res.fixes_simulated ?? []).map((f) => f.label).join('; ')}</p>
              <ul>{(res.paths?.removed ?? []).map((p, i) => <li key={i}><code>{p.route}</code></li>)}</ul>
            </div>
          )}
        </>
      )}
    </section>
  )
}

// A crash in this card must never blank the whole app: show a small message instead.
class Boundary extends Component<{ children: ReactNode }, { err: Error | null }> {
  state = { err: null as Error | null }
  static getDerivedStateFromError(err: Error) { return { err } }
  componentDidCatch(err: Error) { console.error('SimulationCard crashed:', err) }
  render() {
    return this.state.err
      ? <p className="warn">The simulation panel failed to render: {this.state.err.message}</p>
      : this.props.children
  }
}

export default function SimulationCard({ scenarioId }: { scenarioId: string }) {
  return <Boundary><SimulationCardInner scenarioId={scenarioId} /></Boundary>
}
