import type { ReactNode } from 'react'
import { styleOf } from './style'
import { backupsForFix, bestLikelihood, bestRisk, compromisedFrom, fmtScore, lostForFix, nameOf, relLabel, remediationFor, routeText, routesThrough } from './model'
import type { Model } from './model'
import type { AttackPath, PathsResponse } from './types'

const SCORE_NOTE = 'Relative route score from 0 to 1 (how easy the route looks under the model). Not a probability of attack.'

interface Props {
  model: Model
  paths: PathsResponse
  warnings: string[]
  selEdge: string | null
  selNode: string | null
  attacker: string | null
  selFix: string | null
  onFix: (id: string | null) => void
  onNode: (id: string) => void
  onBack: () => void
}

function Chip({ m, id, onNode }: { m: Model; id: string; onNode: (id: string) => void }) {
  const n = m.nodeById.get(id)
  const st = styleOf(n?.entity_type ?? '')
  return (
    <button className="nodechip" onClick={() => onNode(id)} title={id}>
      <span className="dot" style={{ background: st.color }}>{st.glyph}</span>
      {nameOf(m, id)}
    </button>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="sec">
      <h3>{title}</h3>
      {children}
    </section>
  )
}

function Feas({ f }: { f: AttackPath['feasibility'] }) {
  return <span className={`tag ${f === 'conditional' ? 'amber' : 'red'}`}>{f === 'conditional' ? 'conditional' : 'feasible under model'}</span>
}

function Score({ label, v }: { label: string; v: number | null }) {
  return (
    <div className="score">
      <div className="score-top"><span>{label}</span><b>{fmtScore(v)}</b></div>
      <div className="bar"><i style={{ width: `${(v ?? 0) * 100}%` }} /></div>
    </div>
  )
}

function Routes({ m, paths, onNode }: { m: Model; paths: AttackPath[]; onNode: (id: string) => void }) {
  return (
    <ul className="routes">
      {paths.map((p) => (
        <li key={p.path_id}>
          <div className="route-line">
            {p.node_ids.map((id, i) => (
              <span key={id + i} className="route-step">
                {i > 0 && <span className="arrow">→</span>}
                <Chip m={m} id={id} onNode={onNode} />
              </span>
            ))}
          </div>
          <div className="route-meta">
            <Feas f={p.feasibility} />
            <span>likelihood {fmtScore(p.likelihood_score)}</span>
            <span>risk {fmtScore(p.risk_score)}</span>
            <span>confidence {p.confidence}</span>
          </div>
          {p.score_unknowns.length > 0 && <div className="warn small">Score unknown: {p.score_unknowns.join('; ')}</div>}
        </li>
      ))}
    </ul>
  )
}

function RiskBlock({ paths }: { paths: AttackPath[] }) {
  return (
    <>
      <Score label="Highest likelihood" v={bestLikelihood(paths)} />
      <Score label="Highest risk" v={bestRisk(paths)} />
      <p className="note">{SCORE_NOTE}</p>
    </>
  )
}

function EdgePanel({ p }: { p: Props }) {
  const m = p.model
  const e = m.edgeById.get(p.selEdge as string)
  if (!e) return null
  const used = m.pathsByEdge.get(e.edge_id) ?? []
  const attack = used.length > 0
  const targets = [...new Set(used.map((x) => x.target_node_id))]
  const downstream = new Set<string>()
  for (const x of used) {
    const at = x.edge_ids.indexOf(e.edge_id)
    x.node_ids.slice(at + 1).forEach((id) => downstream.add(id))
  }
  return (
    <>
      <header className="ph">
        <span className={`tag ${attack ? 'red' : 'gray'}`}>{attack ? 'Attack arrow' : 'Relationship'}</span>
        <h2>{relLabel(e.relation_type)}</h2>
      </header>
      <Section title="Endpoints">
        <div className="endpoints">
          <div><small>From</small><Chip m={m} id={e.source_id} onNode={p.onNode} /></div>
          <span className="arrow big">→</span>
          <div><small>To</small><Chip m={m} id={e.target_id} onNode={p.onNode} /></div>
        </div>
        {attack && (
          <p className="note">
            Used by {used.length} attack route{used.length === 1 ? '' : 's'} starting from{' '}
            {[...new Set(used.map((x) => nameOf(m, x.entry_node_id)))].join(', ')}.
          </p>
        )}
      </Section>
      {attack ? (
        <>
          <Section title="Data compromised">
            {targets.map((t) => {
              const pol = m.policiesOf.get(t) ?? []
              return (
                <div key={t} className="data-row">
                  <Chip m={m} id={t} onNode={p.onNode} />
                  <span className="tag dark">target</span>
                  <div className="note">{pol.length ? `Holds: ${pol.join(', ')}` : 'No attached policies listed in this snapshot.'}</div>
                </div>
              )
            })}
            {[...downstream].filter((id) => !targets.includes(id)).length > 0 && (
              <div className="note">
                Also taken over on the way:{' '}
                {[...downstream].filter((id) => !targets.includes(id)).map((id) => (
                  <Chip key={id} m={m} id={id} onNode={p.onNode} />
                ))}
              </div>
            )}
            <p className="note">Everything these identities are allowed to do becomes reachable. This is a modeled possibility, not evidence of an incident.</p>
          </Section>
          <Section title="Likelihood and risk">
            <RiskBlock paths={used} />
          </Section>
          <Section title={`Attack routes using this arrow (${used.length})`}>
            <Routes m={m} paths={used} onNode={p.onNode} />
          </Section>
        </>
      ) : (
        <p className="note">This relationship is not part of any attack route.</p>
      )}
      <Section title="Evidence">
        <dl className="kv">
          <dt>Status</dt><dd>{e.status}</dd>
          <dt>Conditions</dt><dd>{Object.keys(e.conditions).length ? JSON.stringify(e.conditions) : 'none recorded'}</dd>
          <dt>Evidence</dt><dd>{e.evidence_ids.length ? e.evidence_ids.map((x) => x.split('/').pop()).join(', ') : 'none'}</dd>
        </dl>
        {e.status === 'inferred' && <p className="note">Inferred from policy text, not confirmed. Routes using it stay conditional.</p>}
      </Section>
    </>
  )
}

function AttackNodePanel({ p }: { p: Props }) {
  const m = p.model
  const id = p.selNode as string
  const comp = compromisedFrom(m, id)
  const routes = m.pathsByEntry.get(id) ?? []
  return (
    <>
      <header className="ph">
        <span className="tag red">Attack node</span>
        <h2>{nameOf(m, id)}</h2>
      </header>
      <p className="lead">
        If this identity is compromised, {comp.length} node{comp.length === 1 ? '' : 's'} can be reached over {routes.length} route
        {routes.length === 1 ? '' : 's'}. They are highlighted on the map.
      </p>
      <Section title="Likelihood and risk">
        <RiskBlock paths={routes} />
      </Section>
      <Section title={`Compromised nodes (${comp.length})`}>
        <p className="note">Click one to see how to fix it.</p>
        <ul className="list">
          {comp.map((c) => (
            <li key={c.node.entity_id}>
              <button className="rowbtn" onClick={() => p.onNode(c.node.entity_id)}>
                <span className="dot" style={{ background: styleOf(c.node.entity_type).color }}>{styleOf(c.node.entity_type).glyph}</span>
                <span className="grow">{c.node.name}</span>
                <span className={`tag ${c.isTarget ? 'dark' : 'gray'}`}>{c.isTarget ? 'target' : 'pivot'}</span>
                <span className="num">risk {fmtScore(bestRisk(c.routes))}</span>
              </button>
            </li>
          ))}
        </ul>
      </Section>
      <Section title={`Attack routes (${routes.length})`}>
        <Routes m={m} paths={routes} onNode={p.onNode} />
      </Section>
    </>
  )
}

function CompromisedPanel({ p }: { p: Props }) {
  const m = p.model
  const id = p.selNode as string
  const rem = remediationFor(m, id, p.attacker)
  const pol = m.policiesOf.get(id) ?? []
  const covered = rem.routes.length - rem.uncovered.length
  return (
    <>
      <header className="ph">
        {p.attacker && (
          <button className="back" onClick={p.onBack}>← Compromised by {nameOf(m, p.attacker)}</button>
        )}
        <span className="tag dark">{m.targetIds.has(id) ? 'Compromised target' : 'Compromised pivot'}</span>
        <h2>{nameOf(m, id)}</h2>
      </header>
      <p className="lead">
        {rem.routes.length} attack route{rem.routes.length === 1 ? '' : 's'} reach this node
        {p.attacker ? ` from ${nameOf(m, p.attacker)}` : ''}.
        {pol.length > 0 && ` It holds: ${pol.join(', ')}.`}
      </p>
      <Section title="Remediation methods">
        {!m.fixesAvailable && <p className="warn">Remediation data is unavailable (the overlays endpoint did not respond).</p>}
        {m.fixesAvailable && rem.rows.length === 0 && (
          <p className="warn">No proposed fix cuts a route to this node. It stays exposed under the current recommendations.</p>
        )}
        {rem.rows.map(({ fix, blocks }) => {
          const edge = m.edgeById.get(fix.edge_ids[0])
          return (
            <div key={fix.id} className={`fix${p.selFix === fix.id ? ' selected' : ''}`}>
              <div className="fix-top">
                <b>{fix.label}</b>
                <span className="tag green">blocks {blocks.length} of {rem.routes.length}</span>
              </div>
              {edge && (
                <div className="fix-cut">
                  Cut: <i>{relLabel(edge.relation_type)}</i> <Chip m={m} id={edge.source_id} onNode={p.onNode} />
                  <span className="arrow">→</span> <Chip m={m} id={edge.target_id} onNode={p.onNode} />
                </div>
              )}
              {backupsForFix(m, fix).map((b) => (  <p className="note" key={b.id}>↪ Access keeps working via: <b>{routeText(b)}</b></p>))}
              {lostForFix(m, fix).map((a) => (  <div className="warn small" key={a.id}>    ⚠ Breaks {a.label.replace('No verified backup | ', '')}: no verified backup found    {a.note.includes('depth-limited') ? ' (search was depth-limited)' : ''}.  </div>))}
              <button className="btn" onClick={() => p.onFix(p.selFix === fix.id ? null : fix.id)}>
                {p.selFix === fix.id ? 'Hide on map' : 'Show on map'}
              </button>
              <p className="note">{fix.note}</p>
            </div>
          )
        })}
        {m.fixesAvailable && rem.rows.length > 0 && (
          <p className="note">
            Applying all of these blocks {covered} of {rem.routes.length} route{rem.routes.length === 1 ? '' : 's'} to this node.
            {rem.uncovered.length > 0 && ` ${rem.uncovered.length} would remain.`}
          </p>
        )}
        {rem.rows.length > 0 && (
          <p className="note">
            "Risk reduction" in a fix note is the share of total modeled route risk that fix removes. It is not
            target-asset impact.
          </p>
        )}
        <p className="note strong">Simulation only. Every change to an NHI needs human approval and nothing is applied to AWS.</p>
      </Section>
      <Section title="Likelihood and risk">
        <RiskBlock paths={rem.routes} />
      </Section>
      <Section title={`Routes reaching this node (${rem.routes.length})`}>
        <Routes m={m} paths={rem.routes} onNode={p.onNode} />
      </Section>
    </>
  )
}

function PlainNodePanel({ p }: { p: Props }) {
  const m = p.model
  const id = p.selNode as string
  const n = m.nodeById.get(id)
  const pol = m.policiesOf.get(id) ?? []
  return (
    <>
      <header className="ph">
        <span className="tag gray">{styleOf(n?.entity_type ?? '').label}</span>
        <h2>{nameOf(m, id)}</h2>
      </header>
      <p className="note">This node is not on any attack route.</p>
      <dl className="kv">
        <dt>Type</dt><dd>{n?.entity_type}</dd>
        <dt>Account</dt><dd>{n?.account_id ?? 'unknown'}</dd>
        <dt>Identity class</dt><dd>{n?.identity_class}</dd>
        <dt>Policies</dt><dd>{pol.length ? pol.join(', ') : 'none listed'}</dd>
      </dl>
    </>
  )
}

function Overview({ p }: { p: Props }) {
  const m = p.model
  const entries = [...m.attackNodeIds]
  return (
    <>
      <header className="ph"><h2>Overview</h2></header>
      <p className="lead">
        {m.attackPaths.length} attack route{m.attackPaths.length === 1 ? '' : 's'} from {entries.length} attack node
        {entries.length === 1 ? '' : 's'}. {m.blockedCount > 0 && `${m.blockedCount} blocked route(s) are not counted.`}
      </p>
      <ul className="howto">
        <li>Click an <b>attack node</b> (red ring with !) to see everything it compromises.</li>
        <li>Click a <b>compromised node</b> to see how to fix it.</li>
        <li>Click a <b>red arrow</b> to see the data compromised, endpoints, likelihood and risk.</li>
      </ul>
      {p.paths.search.truncated && (
        <p className="warn">Path search was truncated ({p.paths.search.truncation_reason}). More routes may exist.</p>
      )}
      {p.warnings.map((w) => <p key={w} className="warn small">{w}</p>)}
      <Section title="Attack nodes">
        <ul className="list">
          {entries.map((id) => {
            const r = m.pathsByEntry.get(id) ?? []
            return (
              <li key={id}>
                <button className="rowbtn" onClick={() => p.onNode(id)}>
                  <span className="dot" style={{ background: styleOf(m.nodeById.get(id)?.entity_type ?? '').color }}>
                    {styleOf(m.nodeById.get(id)?.entity_type ?? '').glyph}
                  </span>
                  <span className="grow">{nameOf(m, id)}</span>
                  <span className="num">{r.length} route{r.length === 1 ? '' : 's'}</span>
                  <span className="num">risk {fmtScore(bestRisk(r))}</span>
                </button>
              </li>
            )
          })}
        </ul>
      </Section>
      <Section title="Rerouting after proposed fixes">
        {!m.fixesAvailable && <p className="warn">Overlay data is unavailable.</p>}
        {m.overlayWarnings.map((w) => <p key={w} className="warn small">{w}</p>)}
        {m.summary && (
          <p className="note">
            Optimizer relative score, all {m.summary.fixes} proposed fixes: {m.summary.risk_before} → {m.summary.risk_after};
            {' '}{m.summary.paths_left} path(s) left. This is not target-asset impact.
          </p>
        )}
        {m.backups.map((b) => (
          <div key={b.id} className="fix">
            <b>{b.label}</b>
            <p className="note">{b.note}</p>
            <p className="note">"Scenario risk" here is target-asset impact (per the handoff). Tick "Show rerouting" to see it on the map.</p>
          </div>
        ))}
        {m.accessLost.map((l) => (
          <div key={l.id} className="fix">
            <b>{l.label}</b>
            <p className="warn small">{l.note}</p>
          </div>
        ))}
        {m.backups.length === 0 && m.accessLost.length === 0 && (
          <p className="note">
            No backup routes or lost access reported. If this scenario has no access sidecar, that means not checked, not safe.
          </p>
        )}
      </Section>
      <Section title="How to read the scores">
        <p className="note">{SCORE_NOTE}</p>
        {p.paths.assumptions.map((a) => <p key={a} className="note">{a}</p>)}
      </Section>
    </>
  )
}

export default function Inspector(p: Props) {
  const m = p.model
  let body: ReactNode
  if (p.selEdge) body = <EdgePanel p={p} />
  else if (p.selNode && p.attacker && p.selNode === p.attacker) body = <AttackNodePanel p={p} />
  else if (p.selNode && (p.attacker || routesThrough(m, p.selNode, null).length > 0)) body = <CompromisedPanel p={p} />
  else if (p.selNode) body = <PlainNodePanel p={p} />
  else body = <Overview p={p} />
  return <aside className="panel">{body}</aside>
}