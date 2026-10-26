'use client'

/**
 * ScanCompareDialog — side-by-side comparison of two saved scans.
 * Shows KPI deltas (best speed / avg latency / alive ratio / clean IPs),
 * a grouped bar chart of shared IPs, and a per-IP delta table.
 */

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { faIR, enUS, type Locale } from 'date-fns/locale'
import {
  ArrowDownRight,
  ArrowUpRight,
  GitCompareArrows,
  Loader2,
  Minus,
} from 'lucide-react'
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
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { fetchJson, type ScanDetailResponse, type ScanListItem } from '@/lib/api-types'
import { getPreset } from '@/lib/cdn-presets'
import { formatBytesPerSec, formatLatency } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import { cn } from '@/lib/utils'

const BAR_A = '#a1a1aa' // zinc-400 (older scan)
const BAR_B = '#10b981' // emerald-500 (newer scan)

interface ScanCompareDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  scans: ScanListItem[]
}

function scanLabel(s: ScanListItem, lang: 'fa' | 'en', dateFnsLocale: Locale): string {
  const t = formatDistanceToNow(new Date(s.createdAt), { addSuffix: true, locale: dateFnsLocale })
  const preset =
    lang === 'fa' ? (getPreset(s.preset)?.nameFa ?? s.preset) : (getPreset(s.preset)?.name ?? s.preset)
  return `${preset} — ${t}`
}

function mbps(bps: number): number {
  return Math.round((bps / (1024 * 1024)) * 100) / 100
}

/** delta chip: up = higher value, good = depends on metric semantics */
function DeltaChip({
  pct,
  goodWhenUp,
}: {
  pct: number | null
  goodWhenUp: boolean
}) {
  const { t } = useI18n()
  if (pct == null || !Number.isFinite(pct)) {
    return (
      <span className="inline-flex items-center gap-0.5 text-[11px] text-muted-foreground">
        <Minus className="size-3" aria-hidden /> —
      </span>
    )
  }
  const rounded = Math.abs(pct) < 0.5 ? 0 : Math.round(pct * 10) / 10
  if (rounded === 0) {
    return (
      <span className="inline-flex items-center gap-0.5 text-[11px] text-muted-foreground">
        <Minus className="size-3" aria-hidden /> {t('compare.delta.none')}
      </span>
    )
  }
  const up = rounded > 0
  const good = up === goodWhenUp
  return (
    <span
      className={cn(
        'inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 text-[11px] font-semibold',
        good
          ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
          : 'bg-red-500/10 text-red-500',
      )}
      dir="ltr"
    >
      {up ? <ArrowUpRight className="size-3" aria-hidden /> : <ArrowDownRight className="size-3" aria-hidden />}
      {Math.abs(rounded)}%
    </span>
  )
}

function KpiCompare({
  label,
  valueA,
  valueB,
  pct,
  goodWhenUp,
  unit,
}: {
  label: string
  valueA: string
  valueB: string
  pct: number | null
  goodWhenUp: boolean
  unit?: string
}) {
  return (
    <div className="rounded-lg border bg-background/40 p-3">
      <div className="text-[10px] font-medium text-muted-foreground">{label}</div>
      <div className="mt-1.5 space-y-1" dir="ltr">
        <div className="flex items-center justify-between gap-1 font-mono text-xs">
          <span className="inline-flex items-center gap-1 text-muted-foreground">
            <span className="size-2 rounded-full" style={{ background: BAR_A }} aria-hidden />
            A
          </span>
          <span className="font-semibold tabular-nums">
            {valueA}
            {unit ? <span className="mr-1 text-[10px] text-muted-foreground">{unit}</span> : null}
          </span>
        </div>
        <div className="flex items-center justify-between gap-1 font-mono text-xs">
          <span className="inline-flex items-center gap-1 text-muted-foreground">
            <span className="size-2 rounded-full" style={{ background: BAR_B }} aria-hidden />
            B
          </span>
          <span className="font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">
            {valueB}
            {unit ? <span className="mr-1 text-[10px] text-muted-foreground">{unit}</span> : null}
          </span>
        </div>
      </div>
      <div className="mt-2 flex justify-end">
        <DeltaChip pct={pct} goodWhenUp={goodWhenUp} />
      </div>
    </div>
  )
}

export function ScanCompareDialog({ open, onOpenChange, scans }: ScanCompareDialogProps) {
  const { t, num, lang, dir } = useI18n()
  const [pickedA, setPickedA] = useState<string | null>(null)
  const [pickedB, setPickedB] = useState<string | null>(null)

  const usable = useMemo(() => scans.filter((s) => s.resultCount > 0), [scans])
  const dateFnsLocale = lang === 'fa' ? faIR : enUS

  // effective selection with sensible defaults: A = second newest (older), B = newest
  const idA = pickedA ?? usable[1]?.id ?? null
  const idB = pickedB ?? usable[0]?.id ?? null

  const detailA = useQuery<ScanDetailResponse>({
    queryKey: ['scan-detail', idA, 'compare'],
    queryFn: () => fetchJson<ScanDetailResponse>(`/api/scans/${idA}`),
    enabled: open && !!idA,
  })
  const detailB = useQuery<ScanDetailResponse>({
    queryKey: ['scan-detail', idB, 'compare'],
    queryFn: () => fetchJson<ScanDetailResponse>(`/api/scans/${idB}`),
    enabled: open && !!idB,
  })

  const loading = !detailA.data || !detailB.data
  const bothLoaded = !!detailA.data && !!detailB.data

  const analysis = useMemo(() => {
    if (!detailA.data || !detailB.data) return null
    const A = detailA.data
    const B = detailB.data
    // NOTE: the detail endpoint does not return list-level aggregates — compute from results
    const bestSpeedOf = (d: ScanDetailResponse) =>
      d.results.reduce((m, r) => Math.max(m, r.totalSpeed ?? 0), 0)
    const avgLatencyOf = (d: ScanDetailResponse) =>
      d.results.length
        ? d.results.reduce((s, r) => s + (r.latencyMs ?? 0), 0) / d.results.length
        : 0
    const kpi = {
      bestSpeed: { a: bestSpeedOf(A), b: bestSpeedOf(B) },
      avgLatency: { a: avgLatencyOf(A), b: avgLatencyOf(B) },
      aliveRatio: {
        a: A.scan.totalIPs > 0 ? (A.scan.aliveIPs / A.scan.totalIPs) * 100 : 0,
        b: B.scan.totalIPs > 0 ? (B.scan.aliveIPs / B.scan.totalIPs) * 100 : 0,
      },
      cleanIPs: { a: A.scan.resultCount, b: B.scan.resultCount },
    }
    const pct = (x: number, y: number): number | null =>
      x > 0 ? ((y - x) / x) * 100 : null

    const mapA = new Map(A.results.map((r) => [r.ip, r]))
    const shared = B.results
      .filter((r) => mapA.has(r.ip))
      .map((r) => {
        const a = mapA.get(r.ip)!
        return {
          ip: r.ip,
          latA: a.latencyMs,
          latB: r.latencyMs,
          spdA: a.totalSpeed,
          spdB: r.totalSpeed,
        }
      })
      .sort((x, y) => Math.max(y.spdA, y.spdB) - Math.max(x.spdA, x.spdB))
      .slice(0, 8)

    return { kpi, pct, shared }
  }, [detailA.data, detailB.data])

  const noShared = bothLoaded && analysis?.shared.length === 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent dir={dir} className="max-h-[88vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <GitCompareArrows className="size-5 text-emerald-600 dark:text-emerald-400" aria-hidden />
            {t('compare.title')}
          </DialogTitle>
          <DialogDescription>
            {t('compare.desc')}
          </DialogDescription>
        </DialogHeader>

        {/* selectors */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
              <span className="size-2 rounded-full" style={{ background: BAR_A }} aria-hidden />
              {t('compare.a')}
            </div>
            <Select value={idA ?? ''} onValueChange={(v) => setPickedA(v)}>
              <SelectTrigger className="h-10 w-full text-xs" aria-label={t('compare.select.aria.a')}>
                <SelectValue placeholder={t('compare.select.placeholder')} />
              </SelectTrigger>
              <SelectContent>
                {usable.map((s) => (
                  <SelectItem key={s.id} value={s.id} className="text-xs">
                    {scanLabel(s, lang, dateFnsLocale)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
              <span className="size-2 rounded-full" style={{ background: BAR_B }} aria-hidden />
              {t('compare.b')}
            </div>
            <Select value={idB ?? ''} onValueChange={(v) => setPickedB(v)}>
              <SelectTrigger className="h-10 w-full text-xs" aria-label={t('compare.select.aria.b')}>
                <SelectValue placeholder={t('compare.select.placeholder')} />
              </SelectTrigger>
              <SelectContent>
                {usable.map((s) => (
                  <SelectItem key={s.id} value={s.id} className="text-xs">
                    {scanLabel(s, lang, dateFnsLocale)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {usable.length < 2 ? (
          <p className="rounded-lg border border-dashed py-6 text-center text-xs text-muted-foreground">
            {t('compare.needtwo')}
          </p>
        ) : null}

        {loading && usable.length >= 2 ? (
          <div className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" aria-hidden />
            {t('compare.loading')}
          </div>
        ) : null}

        {bothLoaded && analysis ? (
          <div className="space-y-5">
            {/* KPI deltas */}
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <KpiCompare
                label={t('compare.kpi.bestspeed')}
                valueA={mbps(analysis.kpi.bestSpeed.a).toString()}
                valueB={mbps(analysis.kpi.bestSpeed.b).toString()}
                pct={analysis.pct(analysis.kpi.bestSpeed.a, analysis.kpi.bestSpeed.b)}
                goodWhenUp
                unit="MB/s"
              />
              <KpiCompare
                label={t('compare.kpi.avglatency')}
                valueA={Math.round(analysis.kpi.avgLatency.a).toString()}
                valueB={Math.round(analysis.kpi.avgLatency.b).toString()}
                pct={analysis.pct(analysis.kpi.avgLatency.a, analysis.kpi.avgLatency.b)}
                goodWhenUp={false}
                unit="ms"
              />
              <KpiCompare
                label={t('compare.kpi.aliveratio')}
                valueA={`${analysis.kpi.aliveRatio.a.toFixed(1)}`}
                valueB={`${analysis.kpi.aliveRatio.b.toFixed(1)}`}
                pct={analysis.pct(analysis.kpi.aliveRatio.a, analysis.kpi.aliveRatio.b)}
                goodWhenUp
                unit="%"
              />
              <KpiCompare
                label={t('compare.kpi.clean')}
                valueA={analysis.kpi.cleanIPs.a.toString()}
                valueB={analysis.kpi.cleanIPs.b.toString()}
                pct={analysis.pct(analysis.kpi.cleanIPs.a, analysis.kpi.cleanIPs.b)}
                goodWhenUp
              />
            </div>

            {/* shared IPs chart */}
            {analysis.shared.length > 0 ? (
              <div>
                <div className="mb-2 text-xs font-semibold text-muted-foreground">
                  {t('compare.shared.title')}
                </div>
                <div className="h-56 w-full rounded-lg border bg-background/40 p-2" dir="ltr">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={analysis.shared} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="currentColor" opacity={0.12} vertical={false} />
                      <XAxis
                        dataKey="ip"
                        tick={{ fontSize: 10, fill: 'currentColor', opacity: 0.65 }}
                        tickFormatter={(v: string) => v.split('.').slice(0, 3).join('.') + '…'}
                        interval={0}
                      />
                      <YAxis tick={{ fontSize: 10, fill: 'currentColor', opacity: 0.65 }} width={34} />
                      <Tooltip
                        contentStyle={{
                          background: 'hsl(var(--card))',
                          border: '1px solid hsl(var(--border))',
                          borderRadius: 8,
                          fontSize: 12,
                          direction: 'ltr',
                        }}
                        formatter={(value: number | string) => `${Number(value).toFixed(2)} MB/s`}
                      />
                      <Legend wrapperStyle={{ fontSize: 11 }} />
                      <Bar dataKey="spdA" name={t('compare.a')} fill={BAR_A} radius={[3, 3, 0, 0]} />
                      <Bar dataKey="spdB" name={t('compare.b')} fill={BAR_B} radius={[3, 3, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            ) : null}

            {noShared ? (
              <p className="rounded-lg border border-dashed py-5 text-center text-xs text-muted-foreground">
                {t('compare.shared.empty')}
              </p>
            ) : null}

            {/* shared IPs table */}
            {analysis.shared.length > 0 ? (
              <div>
                <div className="mb-2 text-xs font-semibold text-muted-foreground">
                  {t('compare.detail.title')}
                </div>
                <div className="scrollbar-thin max-h-64 overflow-y-auto rounded-lg border">
                  <Table>
                    <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="text-start text-xs">{t('compare.col.ip')}</TableHead>
                        <TableHead className="text-start text-xs">{t('compare.col.lat')}</TableHead>
                        <TableHead className="text-start text-xs">{t('compare.col.speed')}</TableHead>
                        <TableHead className="text-start text-xs">{t('compare.col.delta')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {analysis.shared.map((r) => {
                        const dpct =
                          r.spdA > 0 ? ((r.spdB - r.spdA) / r.spdA) * 100 : null
                        return (
                          <TableRow key={r.ip}>
                            <TableCell dir="ltr" className="text-left font-mono text-xs">
                              {r.ip}
                            </TableCell>
                            <TableCell dir="ltr" className="text-left font-mono text-xs tabular-nums">
                              {formatLatency(r.latA)} → {formatLatency(r.latB)}
                            </TableCell>
                            <TableCell dir="ltr" className="text-left font-mono text-xs tabular-nums">
                              {r.spdA > 0 ? formatBytesPerSec(r.spdA) : '—'} →{' '}
                              <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                                {r.spdB > 0 ? formatBytesPerSec(r.spdB) : '—'}
                              </span>
                            </TableCell>
                            <TableCell>
                              <DeltaChip pct={dpct} goodWhenUp />
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                </div>
              </div>
            ) : null}

            <div className="flex items-center justify-between text-[11px] text-muted-foreground">
              <span>
                A: {t('compare.footer.alive', { total: num(detailA.data.scan.totalIPs), alive: num(detailA.data.scan.aliveIPs) })}
              </span>
              <Badge variant="outline" className="text-[10px]">
                {t('compare.badge.db')}
              </Badge>
              <span>
                B: {t('compare.footer.alive', { total: num(detailB.data.scan.totalIPs), alive: num(detailB.data.scan.aliveIPs) })}
              </span>
            </div>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
