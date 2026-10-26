'use client'

/**
 * LatencyHistogram — distribution of responsive-IP latencies in buckets.
 * Pure client-side chart fed by the live results list.
 */

import { useMemo } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { LiveResult } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'

interface Bucket {
  label: string
  count: number
  color: string
}

const BUCKETS: { max: number; from: number; color: string }[] = [
  { max: 20, from: 0, color: '#10b981' },
  { max: 50, from: 20, color: '#14b8a6' },
  { max: 100, from: 50, color: '#84cc16' },
  { max: 200, from: 100, color: '#eab308' },
  { max: 400, from: 200, color: '#f97316' },
  { max: 800, from: 400, color: '#ef4444' },
  { max: Infinity, from: 800, color: '#a1a1aa' },
]

export function LatencyHistogram({ results }: { results: LiveResult[] }) {
  const { t, num } = useI18n()

  const data = useMemo<Bucket[]>(() => {
    const counts = new Array(BUCKETS.length).fill(0)
    for (const r of results) {
      const ms = r.latencyMs
      const idx = BUCKETS.findIndex((b) => ms <= b.max)
      counts[idx === -1 ? BUCKETS.length - 1 : idx]++
    }
    return BUCKETS.map((b, i) => ({
      label: b.max === Infinity ? `${num(b.from)}+` : `${num(b.from)}-${num(b.max)}`,
      count: counts[i],
      color: b.color,
    }))
  }, [results, num])

  const total = results.length
  if (total === 0) return null

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur">
      <div className="mb-1 flex items-center justify-between">
        <h3 className="text-xs font-bold text-foreground">{t('hist.title')}</h3>
        <span className="text-[10px] text-muted-foreground">
          {t('hist.sub', { n: num(total) })}
        </span>
      </div>
      <div className="h-40" dir="ltr">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 4, left: -18, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.15)" vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 9, fill: 'currentColor', opacity: 0.6 }}
              axisLine={false}
              tickLine={false}
              interval={0}
            />
            <YAxis
              tick={{ fontSize: 9, fill: 'currentColor', opacity: 0.6 }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              cursor={{ fill: 'rgba(16,185,129,0.06)' }}
              contentStyle={{
                background: 'rgba(9,9,11,0.92)',
                border: '1px solid rgba(16,185,129,0.25)',
                borderRadius: 8,
                fontSize: 11,
                direction: 'rtl',
              }}
              formatter={(value: number) => [`${num(value)} IP`, t('hist.tip')]}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} fillOpacity={0.85} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
