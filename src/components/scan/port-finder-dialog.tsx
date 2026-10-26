'use client'

import { useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import { Cable, Check, Copy, Loader2, Network, Play, Square, Zap } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
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
import { cn } from '@/lib/utils'
import { formatLatency, type XrayProbeResult } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'
import { SCORE_BAND_HEX, scoreBand } from '@/lib/ip-score'

/** standard TLS ports CDNs (Cloudflare in particular) serve HTTPS-style proxies on */
const PROBE_PORTS = [443, 2053, 2083, 2087, 2096, 8443] as const
const CONCURRENCY = 2

type ProbeGrade = NonNullable<XrayProbeResult['grade']>

const GRADE_STYLES: Record<ProbeGrade, string> = {
  excellent: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  good: 'border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400',
  weak: 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  fail: 'border-red-500/40 bg-red-500/10 text-red-500',
}

export interface PortFinderDialogProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  /** IP preselected when the dialog opens */
  defaultIp?: string
  /** top ranked IPs offered in the target selector */
  ipOptions: string[]
  /** SNI host presented during the probes */
  host: string
  /** base port of the current scan (preselects the selector) */
  basePort: number
  connected: boolean
  onProbe: (payload: { ip: string; port: number; host: string }) => Promise<XrayProbeResult | null>
  /** hand the best port to the Xray config dialog (IP:port combos) */
  onUsePort?: (port: number, ip: string) => void
}

export function PortFinderDialog({
  open,
  onOpenChange,
  defaultIp,
  ipOptions,
  host,
  basePort,
  connected,
  onProbe,
  onUsePort,
}: PortFinderDialogProps) {
  const { t, num, dir } = useI18n()
  const [ip, setIp] = useState<string>(defaultIp ?? ipOptions[0] ?? '')
  const [results, setResults] = useState<Record<number, XrayProbeResult | null>>({})
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null)
  const cancelRef = useRef(false)
  const [copied, setCopied] = useState<string | null>(null)

  const running = progress !== null
  const targetIp = ip || ipOptions[0] || ''

  const bestPort = useMemo(() => {
    const entries = Object.entries(results).map(([k, v]) => [Number(k), v] as [number, XrayProbeResult | null])
    const healthy = entries.filter(
      ([, r]) => r?.ok && (r.grade === 'excellent' || r.grade === 'good'),
    )
    const pool = healthy.length > 0 ? healthy : entries.filter(([, r]) => r?.ok)
    if (pool.length === 0) return null
    pool.sort(
      (a, b) => (a[1]?.tlsMs ?? 9999) - (b[1]?.tlsMs ?? 9999) || (a[1]?.totalMs ?? 9999) - (b[1]?.totalMs ?? 9999),
    )
    return pool[0][0]
  }, [results])

  const healthyPorts = useMemo(
    () =>
      (Object.entries(results).map(([k, v]) => [Number(k), v] as [number, XrayProbeResult | null]))
        .filter(([, r]) => r?.ok && r.grade !== 'fail')
        .sort((a, b) => (a[1]?.tlsMs ?? 9999) - (b[1]?.tlsMs ?? 9999))
        .map(([p]) => p),
    [results],
  )

  const persist = (port: number, res: XrayProbeResult | null) => {
    void fetch('/api/probes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        probes: [
          {
            ip: targetIp,
            host,
            port,
            grade: res?.grade ?? 'fail',
            tcpMs: res?.tcpMs,
            tlsMs: res?.tlsMs,
            httpStatus: res?.httpStatus,
            ok: !!res?.ok && res.grade !== 'fail',
          },
        ],
      }),
    }).catch(() => undefined)
  }

  const run = async () => {
    if (running || !targetIp || !connected) {
      if (!connected) toast.error(t('xray.toast.offline'))
      return
    }
    cancelRef.current = false
    setResults({})
    setProgress({ done: 0, total: PROBE_PORTS.length })
    const collected: Record<number, XrayProbeResult | null> = {}
    let done = 0
    for (let i = 0; i < PROBE_PORTS.length; i += CONCURRENCY) {
      if (cancelRef.current) break
      const chunk = PROBE_PORTS.slice(i, i + CONCURRENCY)
      const out = await Promise.all(
        chunk.map(async (p) => ({ port: p, res: await onProbe({ ip: targetIp, port: p, host }) })),
      )
      for (const { port, res } of out) {
        done++
        collected[port] = res
        persist(port, res)
        setResults((prev) => ({ ...prev, [port]: res }))
      }
      setProgress({ done, total: PROBE_PORTS.length })
    }
    const cancelled = cancelRef.current
    setProgress(null)
    const okCount = Object.values(collected).filter((r) => r?.ok && r.grade !== 'fail').length
    if (cancelled) toast.info(t('port.toast.cancelled'))
    else if (okCount === 0) toast.warning(t('port.toast.none'))
    else toast.success(t('port.toast.done', { n: num(okCount) }))
  }

  const stop = () => {
    cancelRef.current = true
  }

  const copy = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(key)
      window.setTimeout(() => setCopied((c) => (c === key ? null : c)), 1600)
    } catch {
      toast.error(t('results.toast.copy.fail'))
    }
  }

  const options = useMemo(() => {
    const set = new Set(ipOptions)
    if (targetIp) set.add(targetIp)
    return Array.from(set).slice(0, 6)
  }, [ipOptions, targetIp])

  return (
    <Dialog open={open} onOpenChange={(v) => !running && onOpenChange(v)}>
      <DialogContent className="max-w-lg overflow-x-hidden" dir={dir}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-lg bg-teal-500/10 text-teal-600 dark:text-teal-400">
              <Network className="size-4" aria-hidden />
            </span>
            {t('port.title')}
          </DialogTitle>
          <DialogDescription>{t('port.desc', { host })}</DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-[minmax(0,1fr)] gap-3">
          {/* target picker */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-muted-foreground">{t('port.target')}</span>
            <Select value={targetIp} onValueChange={setIp} disabled={running}>
              <SelectTrigger className="h-8 w-44 font-mono text-xs" dir="ltr" aria-label={t('port.target')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent dir="ltr">
                {options.map((o) => (
                  <SelectItem key={o} value={o} className="font-mono text-xs">
                    {o}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Badge variant="outline" className="px-1.5 py-0 font-mono text-[10px]" dir="ltr">
              SNI: {host}
            </Badge>
            {running ? (
              <span className="ms-auto inline-flex items-center gap-1 font-mono text-[10px] text-teal-600 dark:text-teal-400" dir="ltr">
                <Loader2 className="size-3 animate-spin" aria-hidden />
                {progress!.done}/{progress!.total}
              </span>
            ) : null}
          </div>

          {/* run / stop */}
          <div className="flex items-center gap-2">
            {running ? (
              <Button variant="destructive" size="sm" className="h-9 flex-1 gap-1.5" onClick={stop}>
                <Square className="size-3.5" aria-hidden />
                {t('results.batch.stop')}
              </Button>
            ) : (
              <Button
                size="sm"
                className="h-9 flex-1 gap-1.5 bg-gradient-to-l from-teal-600 to-emerald-600 text-white hover:from-teal-500 hover:to-emerald-500"
                onClick={() => void run()}
                disabled={!connected || !targetIp}
              >
                <Play className="size-3.5" aria-hidden />
                {t('port.run')}
              </Button>
            )}
          </div>

          {/* port grid */}
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {PROBE_PORTS.map((p) => {
              const r = results[p]
              const isBest = bestPort === p && !running
              return (
                <div
                  key={p}
                  className={cn(
                    'relative rounded-lg border p-2.5 transition-all',
                    isBest
                      ? 'border-emerald-500/60 bg-emerald-500/[0.07] shadow-[0_0_16px_-6px_rgba(16,185,129,0.55)]'
                      : r
                        ? 'border-border bg-background/60'
                        : 'border-dashed border-border/70 bg-transparent',
                  )}
                >
                  {isBest ? (
                    <span className="absolute -top-2 start-1.5 inline-flex items-center gap-0.5 rounded-full border border-emerald-500/50 bg-background px-1.5 text-[9px] font-bold text-emerald-600 dark:text-emerald-400">
                      <Check className="size-2.5" aria-hidden />
                      {t('port.best')}
                    </span>
                  ) : null}
                  <div className="flex items-center justify-between gap-1">
                    <span className="font-mono text-sm font-bold" dir="ltr">
                      :{num(p)}
                    </span>
                    {r ? (
                      r.grade ? (
                        <span
                          className={cn(
                            'inline-flex items-center rounded-md border px-1 py-0 text-[9px] font-semibold',
                            GRADE_STYLES[r.grade],
                          )}
                        >
                          {t(`xray.grade.${r.grade}` as DictKey)}
                        </span>
                      ) : (
                        <span className="text-[9px] text-red-500" dir="ltr">
                          {r.error ? '✕' : '—'}
                        </span>
                      )
                    ) : (
                      <span className="text-[9px] text-muted-foreground">—</span>
                    )}
                  </div>
                  <div className="mt-1 flex items-center justify-between gap-1 text-[10px] text-muted-foreground">
                    <span dir="ltr" className="font-mono">
                      {r?.tlsMs != null ? `TLS ${formatLatency(r.tlsMs)}` : r?.tcpMs != null ? `TCP ${formatLatency(r.tcpMs)}` : '· · ·'}
                    </span>
                    {r?.ok ? <Check className="size-3 text-emerald-500" aria-hidden /> : null}
                  </div>
                </div>
              )
            })}
          </div>

          {/* actions */}
          {!running && Object.keys(results).length > 0 ? (
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-emerald-500/30 text-emerald-700 hover:bg-emerald-500/10 dark:text-emerald-400"
                onClick={() => void copy(`${targetIp}:${bestPort ?? 443}`, 'best')}
                disabled={bestPort === null}
              >
                {copied === 'best' ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
                {t('port.copy.best', { port: num(bestPort ?? 443) })}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-8 gap-1.5"
                onClick={() => void copy(healthyPorts.map((p) => `${targetIp}:${p}`).join('\n'), 'all')}
                disabled={healthyPorts.length === 0}
              >
                {copied === 'all' ? <Check className="size-3.5" aria-hidden /> : <Zap className="size-3.5" aria-hidden />}
                {t('port.copy.healthy', { n: num(healthyPorts.length) })}
              </Button>
              {onUsePort && bestPort !== null ? (
                <Button
                  size="sm"
                  className="h-8 gap-1.5 bg-emerald-600 text-white hover:bg-emerald-700"
                  onClick={() => {
                    onUsePort(bestPort, targetIp)
                    onOpenChange(false)
                  }}
                  aria-label={t('port.use.xray')}
                >
                  <Cable className="size-3.5" aria-hidden />
                  {t('port.use.xray')}
                </Button>
              ) : null}
            </div>
          ) : null}

          {/* score hint for best port */}
          {!running && bestPort !== null ? (
            <p className="rounded-lg border border-emerald-500/25 bg-emerald-500/[0.05] px-3 py-2 text-[11px] leading-5 text-emerald-800 dark:text-emerald-200">
              {t('port.hint', { port: num(bestPort) })}
            </p>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  )
}
