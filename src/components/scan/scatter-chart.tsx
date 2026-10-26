'use client'

/**
 * ScatterChartPanel — latency (X) vs total speed (Y, MB/s) for every
 * speed-tested IP. The optimal IPs cluster at bottom-left.
 */

import { useMemo } from 'react'
import {
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart as RechartsScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from 'recharts'
import { formatBytesPerSec, formatLatency, type LiveResult } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'

interface Dot {
  ip: string
  latency: number
  speed: number
  download: number
  upload: number
}

export function ScatterChart({ results }: { results: LiveResult[] }) {
  const { t, num } = useI18n()

  const data = useMemo<Dot[]>(
    () =>
      results
        .filter((r) => (r.totalSpeed ?? 0) > 0)
        .map((r) => ({
          ip: r.ip,
          latency: Math.round(r.latencyMs),
          speed: Math.round(((r.totalSpeed ?? 0) / 1048576) * 100) / 100,
          download: Math.round(((r.downloadSpeed ?? 0) / 1048576) * 100) / 100,
          upload: Math.round(((r.uploadSpeed ?? 0) / 1048576) * 100) / 100,
        })),
    [results],
  )

  const withSpeed = data.length
  if (withSpeed === 0) return null

  const maxLatency = Math.max(...data.map((d) => d.latency), 50)
  const medianLatency = [...data.map((d) => d.latency)].sort((a, b) => a - b)[Math.floor(withSpeed / 2)]

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-1">
        <h3 className="text-xs font-bold text-foreground">{t('scatter.title')}</h3>
        <span className="text-[10px] text-muted-foreground">
          {t('scatter.sub', { n: num(withSpeed) })}
        </span>
      </div>
      <div className="h-48" dir="ltr">
        <ResponsiveContainer width="100%" height="100%">
          <RechartsScatterChart margin={{ top: 10, right: 12, left: -12, bottom: 4 }}>
            <defs>
              <linearGradient id="scatter-dot" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#10b981" />
                <stop offset="100%" stopColor="#14b8a6" />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.15)" />
            <XAxis
              type="number"
              dataKey="latency"
              name="latency"
              domain={[0, Math.ceil(maxLatency * 1.1)]}
              tick={{ fontSize: 9, fill: 'currentColor', opacity: 0.6 }}
              axisLine={false}
              tickLine={false}
              label={{
                value: 'ms',
                position: 'insideBottomRight',
                offset: -2,
                fontSize: 9,
                opacity: 0.5,
              }}
            />
            <YAxis
              type="number"
              dataKey="speed"
              name="speed"
              tick={{ fontSize: 9, fill: 'currentColor', opacity: 0.6 }}
              axisLine={false}
              tickLine={false}
              width={44}
            />
            <ZAxis range={[50, 50]} />
            <Tooltip
              cursor={{ strokeDasharray: '3 3', stroke: 'rgba(16,185,129,0.4)' }}
              contentStyle={{
                background: 'rgba(9,9,11,0.92)',
                border: '1px solid rgba(16,185,129,0.25)',
                borderRadius: 8,
                fontSize: 11,
                direction: 'ltr',
              }}
              content={({ payload }) => {
                const d = payload?.[0]?.payload as Dot | undefined
                if (!d) return null
                return (
                  <div className="rounded-lg border border-emerald-500/25 bg-zinc-950/95 px-2.5 py-1.5 font-mono text-[11px] text-zinc-200 shadow-xl">
                    <p className="font-semibold text-emerald-400">{d.ip}</p>
                    <p>
                      {t('scatter.tip.latency')}: {formatLatency(d.latency)}
                    </p>
                    <p>
                      {t('scatter.tip.download')}: {formatBytesPerSec(d.download * 1048576)}
                    </p>
                    <p>
                      {t('scatter.tip.upload')}: {formatBytesPerSec(d.upload * 1048576)}
                    </p>
                  </div>
                )
              }}
            />
            {/* median latency reference line (dashed) */}
            <ReferenceLine
              x={medianLatency}
              stroke="rgba(16,185,129,0.35)"
              strokeDasharray="4 4"
              label={{
                value: `median ${medianLatency}ms`,
                position: 'top',
                fontSize: 9,
                fill: 'rgba(16,185,129,0.7)',
              }}
            />
            <Scatter
              data={data}
              fill="url(#scatter-dot)"
              fillOpacity={0.85}
              stroke="#059669"
              strokeOpacity={0.4}
              isAnimationActive={false}
            />
          </RechartsScatterChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
