'use client'

/**
 * ScanTrends — best total speed (MB/s) + avg latency (ms) per saved scan,
 * oldest → newest. Rendered above the history list.
 */

import { useMemo } from 'react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatBytesPerSec, formatLatency } from '@/lib/scan-protocol'
import type { ScanListItem } from '@/lib/api-types'
import { getPreset } from '@/lib/cdn-presets'
import { useI18n } from '@/components/i18n-provider'

export function ScanTrends({ scans }: { scans: ScanListItem[] }) {
  const { t, num, dateLocale, lang } = useI18n()
  const data = useMemo(() => {
    return [...scans]
      .slice(0, 20)
      .reverse()
      .map((s, i) => ({
        idx: i + 1,
        name: `#${i + 1}`,
        preset: lang === 'fa' ? (getPreset(s.preset)?.nameFa ?? s.preset) : s.preset,
        date: new Date(s.createdAt).toLocaleDateString(dateLocale, {
          month: 'short',
          day: 'numeric',
        }),
        bestSpeed: Math.round(((s.bestSpeed ?? 0) / 1048576) * 100) / 100,
        bestSpeedBps: s.bestSpeed ?? 0,
        avgLatency: Math.round((s.avgLatency ?? 0) * 10) / 10,
        alive: s.aliveIPs,
        total: s.totalIPs,
      }))
  }, [scans, dateLocale, lang])

  if (data.length < 2) return null

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <h3 className="flex items-center gap-1.5 text-xs font-bold">
          <span className="flex size-6 items-center justify-center rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
            <svg viewBox="0 0 24 24" className="size-3.5" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
              <path d="M3 3v18h18" strokeLinecap="round" />
              <path d="m7 14 4-4 4 3 5-6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          {t('trends.title')}
        </h3>
        <span className="text-[10px] text-muted-foreground">
          {t('trends.sub')}
        </span>
      </div>
      <div className="h-44" dir="ltr">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 8, right: 8, left: -14, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.15)" />
            <XAxis
              dataKey="name"
              tick={{ fontSize: 9, fill: 'currentColor', opacity: 0.6 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              yAxisId="speed"
              tick={{ fontSize: 9, fill: '#10b981', opacity: 0.8 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              yAxisId="lat"
              orientation="right"
              tick={{ fontSize: 9, fill: '#f59e0b', opacity: 0.8 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                background: 'rgba(9,9,11,0.92)',
                border: '1px solid rgba(16,185,129,0.25)',
                borderRadius: 8,
                fontSize: 11,
                direction: 'rtl',
              }}
              labelFormatter={(label, payload) => {
                const p = payload?.[0]?.payload as
                  | { date?: string; preset?: string; alive?: number; total?: number }
                  | undefined
                return `${p?.preset ?? ''} · ${p?.date ?? ''} — ${t('trends.tip.label', { n: String(label) })} (${num(p?.alive ?? 0)}/${num(p?.total ?? 0)})`
              }}
              formatter={(value: number, name: string) =>
                name === 'bestSpeed'
                  ? [formatBytesPerSec((value * 1048576) as number), t('trends.tip.speed')]
                  : [formatLatency(value as number), t('trends.tip.latency')]
              }
            />
            <Line
              yAxisId="speed"
              type="monotone"
              dataKey="bestSpeed"
              stroke="#10b981"
              strokeWidth={2}
              dot={{ r: 3, fill: '#10b981' }}
              activeDot={{ r: 5 }}
            />
            <Line
              yAxisId="lat"
              type="monotone"
              dataKey="avgLatency"
              stroke="#f59e0b"
              strokeWidth={2}
              strokeDasharray="5 3"
              dot={{ r: 3, fill: '#f59e0b' }}
              activeDot={{ r: 5 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
