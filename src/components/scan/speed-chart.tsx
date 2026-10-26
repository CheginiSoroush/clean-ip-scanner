'use client'

/**
 * SpeedChart — per-IP download vs upload (MB/s) for the speed-tested IPs.
 */

import { useMemo } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatBytesPerSec, type LiveResult } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'

export function SpeedChart({ results }: { results: LiveResult[] }) {
  const { t, num } = useI18n()
  const data = useMemo(() => {
    const withSpeed = results
      .filter((r) => (r.totalSpeed ?? 0) > 0)
      .sort((a, b) => (b.totalSpeed ?? 0) - (a.totalSpeed ?? 0))
      .slice(0, 10)
    return withSpeed.map((r) => ({
      ip: r.ip.split('.').slice(-2).join('.'),
      fullIp: r.ip,
      download: Math.round(((r.downloadSpeed ?? 0) / 1048576) * 100) / 100,
      upload: Math.round(((r.uploadSpeed ?? 0) / 1048576) * 100) / 100,
      totalBps: r.totalSpeed ?? 0,
    }))
  }, [results])

  if (data.length === 0) return null

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur">
      <div className="mb-1 flex items-center justify-between">
        <h3 className="text-xs font-bold text-foreground">{t('speed.title')}</h3>
        <span className="text-[10px] text-muted-foreground">
          {t('speed.sub', { n: num(data.length) })}
        </span>
      </div>
      <div className="h-40" dir="ltr">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 4, left: -18, bottom: 0 }} barGap={2}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.15)" vertical={false} />
            <XAxis
              dataKey="ip"
              tick={{ fontSize: 9, fill: 'currentColor', opacity: 0.6 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 9, fill: 'currentColor', opacity: 0.6 }}
              axisLine={false}
              tickLine={false}
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
              labelFormatter={(label, payload) =>
                (payload?.[0]?.payload as { fullIp?: string })?.fullIp ?? String(label)
              }
              formatter={(value: number, name: string) => [
                formatBytesPerSec(value * 1048576),
                name === 'download' ? t('speed.legend.download') : t('speed.legend.upload'),
              ]}
            />
            <Legend
              formatter={(value: string) =>
                value === 'download' ? t('speed.legend.download') : t('speed.legend.upload')
              }
              wrapperStyle={{ fontSize: 10 }}
            />
            <Bar dataKey="download" fill="#10b981" radius={[3, 3, 0, 0]} maxBarSize={22} />
            <Bar dataKey="upload" fill="#f59e0b" radius={[3, 3, 0, 0]} maxBarSize={22} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
