export const TYPE_STYLE: Record<string, { color: string; glyph: string; label: string }> = {
  iam_user: { color: '#2563eb', glyph: 'U', label: 'User' },
  iam_role: { color: '#7c3aed', glyph: 'R', label: 'Role' },
  iam_policy: { color: '#64748b', glyph: 'P', label: 'Policy' },
}
export const styleOf = (t: string) => TYPE_STYLE[t] ?? { color: '#0d9488', glyph: '•', label: t }
