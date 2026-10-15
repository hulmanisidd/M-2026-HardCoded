import { memo } from 'react'
import {
  BaseEdge, EdgeLabelRenderer, Handle, Position, useInternalNode,
  type EdgeProps, type NodeProps,
} from '@xyflow/react'
import {
  Circle, Database, FileText, Globe, Key, Lock, Server, ShieldCheck, User, Users, Zap,
  type LucideIcon,
} from 'lucide-react'
import type { GraphNode } from './types'

export const TYPE_STYLE: Record<string, { color: string; label: string; Icon: LucideIcon }> = {
  iam_user: { color: '#6366f1', label: 'IAM user', Icon: User },
  iam_role: { color: '#0ea5e9', label: 'IAM role', Icon: ShieldCheck },
  iam_group: { color: '#8b5cf6', label: 'IAM group', Icon: Users },
  iam_policy: { color: '#94a3b8', label: 'Policy', Icon: FileText },
  ec2_instance: { color: '#f59e0b', label: 'EC2 instance', Icon: Server },
  lambda_function: { color: '#f97316', label: 'Lambda', Icon: Zap },
  s3_bucket: { color: '#10b981', label: 'S3 bucket', Icon: Database },
  secret: { color: '#e11d48', label: 'Secret', Icon: Lock },
  kms_key: { color: '#14b8a6', label: 'KMS key', Icon: Key },
  external_principal: { color: '#a855f7', label: 'External', Icon: Globe },
}

export const styleOf = (t: string) =>
  TYPE_STYLE[t] ?? { color: '#94a3b8', label: t, Icon: Circle as LucideIcon }

export type CircleData = {
  e: GraphNode
  r: number
  dim: number
  selected: boolean
  badge: string | null
  [key: string]: unknown
}

const handleStyle = (r: number) => ({
  opacity: 0, pointerEvents: 'none' as const, top: r, left: r, width: 1, height: 1, minWidth: 0,
})

function CircleNodeImpl({ data }: NodeProps) {
  const { e, r, dim, selected, badge } = data as CircleData
  const { color, Icon } = styleOf(e.entity_type)
  const critical = e.criticality === 'critical'
  const ring = critical ? '#e11d48' : color
  const name = e.name.length > 24 ? e.name.slice(0, 23) + '…' : e.name
  return (
    <div
      style={{
        width: r * 2, height: r * 2, borderRadius: '50%', opacity: dim,
        transition: 'opacity .25s ease', position: 'relative', cursor: 'pointer',
      }}
    >
      <div
        style={{
          width: r * 2, height: r * 2, borderRadius: '50%',
          background: `radial-gradient(circle at 30% 24%, #ffffff 0%, #ffffff 40%, ${color}26 100%)`,
          border: `${selected ? 2.5 : 1.5}px solid ${selected ? ring : ring + 'b3'}`,
          boxShadow: selected
            ? `0 0 0 6px ${ring}22, 0 10px 26px ${ring}40`
            : critical
              ? `0 0 0 5px ${ring}14, 0 8px 22px ${ring}33`
              : `0 1px 2px rgba(15,23,42,.06), 0 8px 20px ${ring}26`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          transition: 'box-shadow .25s ease, border-color .25s ease',
        }}
      >
        <Icon size={Math.round(r * 0.9)} color={color} strokeWidth={1.6} />
      </div>
      <div
        style={{
          position: 'absolute', top: r * 2 + 6, left: '50%', transform: 'translateX(-50%)',
          width: 132, textAlign: 'center', pointerEvents: 'none',
        }}
      >
        <div
          style={{
            fontSize: 11, fontWeight: 600, color: '#1e293b', lineHeight: 1.15, wordBreak: 'break-word',
            textShadow: '0 0 6px rgba(245,246,250,1), 0 0 3px rgba(245,246,250,1)',
          }}
        >
          {name}
        </div>
        {badge && (
          <span
            style={{
              display: 'inline-block', marginTop: 3, fontSize: 9, fontWeight: 700, letterSpacing: '.06em',
              textTransform: 'uppercase', color: '#be123c', background: 'rgba(255,228,230,.92)',
              borderRadius: 999, padding: '1px 7px',
            }}
          >
            {badge}
          </span>
        )}
      </div>
      <Handle type="target" position={Position.Top} isConnectable={false} style={handleStyle(r)} />
      <Handle type="source" position={Position.Top} isConnectable={false} style={handleStyle(r)} />
    </div>
  )
}

function FloatingEdgeImpl({ id, source, target, markerEnd, style, data, interactionWidth }: EdgeProps) {
  const s = useInternalNode(source)
  const t = useInternalNode(target)
  if (!s || !t) return null
  const rs = (s.data as CircleData).r
  const rt = (t.data as CircleData).r
  const sc = { x: s.internals.positionAbsolute.x + rs, y: s.internals.positionAbsolute.y + rs }
  const tc = { x: t.internals.positionAbsolute.x + rt, y: t.internals.positionAbsolute.y + rt }
  const dx = tc.x - sc.x
  const dy = tc.y - sc.y
  const len = Math.hypot(dx, dy) || 1
  const ux = dx / len
  const uy = dy / len
  const sx = sc.x + ux * (rs + 2)
  const sy = sc.y + uy * (rs + 2)
  const ex = tc.x - ux * (rt + 6)
  const ey = tc.y - uy * (rt + 6)
  const bend = Math.min(42, len * 0.14)
  const cx = (sx + ex) / 2 - uy * bend
  const cy = (sy + ey) / 2 + ux * bend
  const mx = (sx + 2 * cx + ex) / 4
  const my = (sy + 2 * cy + ey) / 4
  const label = (data as { label?: string } | undefined)?.label
  return (
    <>
      <BaseEdge
        id={id} path={`M${sx},${sy} Q${cx},${cy} ${ex},${ey}`} markerEnd={markerEnd}
        style={style} interactionWidth={interactionWidth}
      />
      {label && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan"
            style={{
              position: 'absolute', transform: `translate(-50%,-50%) translate(${mx}px,${my}px)`,
              fontSize: 10, fontWeight: 600, color: '#334155', background: 'rgba(255,255,255,.88)',
              backdropFilter: 'blur(10px)', border: '1px solid rgba(226,232,240,.9)',
              boxShadow: '0 4px 14px rgba(15,23,42,.08)', borderRadius: 999, padding: '2px 9px',
              pointerEvents: 'none',
            }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}

export const nodeTypes = { circle: memo(CircleNodeImpl) }
export const edgeTypes = { floating: memo(FloatingEdgeImpl) }