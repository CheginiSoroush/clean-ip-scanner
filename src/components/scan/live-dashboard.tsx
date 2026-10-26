'use client'

import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import {
  Activity,
  AreaChart,
  CheckCircle2,
  Dices,
  Gauge,
  TerminalSquare,
} from 'lucide-react'
import {
  Area as RechartsArea,
  AreaChart as RechartsAreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Progress } from '@/components/ui/progress'
import { cn } from '@/lib/utils'
import { formatDurationHMS } from '@/lib/format-fa'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'
import {
  formatLatency,
  type ScanPhase,
  type ScanProgress,
  type ScanSummary,
} from '@/lib/scan-protocol'
import type { LatencyPoint } from '@/hooks/use-scan-socket'
import type { ScanLogLine } from '@/lib/scan-protocol'

interface LiveDashboardProps {
  running: boolean
  phase: ScanPhase
  progress: ScanProgress | null
  summary: ScanSummary | null
  logs: ScanLogLine[]
  latencyHistory: LatencyPoint[]
}

const STEPS: { key: ScanPhase; labelKey: DictKey; icon: React.ElementType }[] = [
  { key: 'generating', labelKey: 'dash.step.generating', icon: Dices },
  { key: 'ping', labelKey: 'dash.step.ping', icon: Activity },
  { key: 'speed', labelKey: 'dash.step.speed', icon: Gauge },
  { key: 'done', labelKey: 'dash.step.done', icon: CheckCircle2 },
]

const LOG_COLORS: Record<ScanLogLine['level'], string> = {
  info: 'text-zinc-400',
  success: 'text-emerald-400',
  warn: 'text-amber-400',
  error: 'text-red-400',
}

function stepIndexFor(phase: ScanPhase): number {
  switch (phase) {
    case 'generating':
      return 0
    case 'ping':
      return 1
    case 'speed':
      return 2
    case 'done':
    case 'stopped':
    case 'error':
      return 3
    default:
      return -1
  }
}

function MiniStat({
  label,
  value,
  accent,
  ltr = false,
}: {
  label: string
  value: React.ReactNode
  accent?: boolean
  ltr?: boolean
}) {
  return (
    <div className="rounded-lg border bg-background/40 p-2.5 text-center sm:text-start">
      <div className="text-[10px] font-medium text-muted-foreground">
        {label}
      </div>
      <div
        dir={ltr ? 'ltr' : undefined}
        className={cn(
          'mt-1 font-mono text-sm font-bold tabular-nums',
          accent && 'text-emerald-500 dark:text-emerald-400'
        )}
      >
        {value}
      </div>
    </div>
  )
}

export function LiveDashboard({
  running,
  phase,
  progress,
  summary,
  logs,
  latencyHistory,
}: LiveDashboardProps) {
  const { t, num, lang } = useI18n()
  const logBoxRef = useRef<HTMLDivElement>(null)
  const anchorRef = useRef<number | null>(null)
  const [, setTick] = useState(0)

  // anchor for smooth client-side elapsed timer (ref only — no cascading renders)
  useEffect(() => {
    if (running && progress) {
      anchorRef.current = Date.now() - progress.elapsedMs
    } else if (!running) {
      anchorRef.current = null
    }
  }, [running, progress])

  // re-render every 500ms while running so the elapsed timer ticks
  useEffect(() => {
    if (!running) return
    const id = window.setInterval(() => setTick((t) => t + 1), 500)
    return () => window.clearInterval(id)
  }, [running])

  const elapsedMs = running
    ? anchorRef.current != null
      ? Math.max(0, Date.now() - anchorRef.current)
      : (progress?.elapsedMs ?? 0)
    : (summary?.elapsedMs ?? 0)

  // auto-scroll terminal
  useEffect(() => {
    const el = logBoxRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [logs])

  const activeStep = stepIndexFor(phase)
  const isFinished =
    phase === 'done' || phase === 'stopped' || phase === 'error'

  // progress computation
  let pct = 0
  let ratioLabel = t('dash.ratio.ready')
  if (running && !progress) {
    pct = 4
    ratioLabel = t('dash.ratio.preparing')
  } else if (progress && running) {
    if (phase === 'generating') {
      pct = 4
      ratioLabel = t('dash.ratio.generating')
    } else if (phase === 'ping') {
      const r = progress.total > 0 ? Math.min(1, progress.scanned / progress.total) : 0
      pct = r * 80
      ratioLabel = t('dash.ratio.ping', { a: num(progress.scanned), b: num(progress.total) })
    } else if (phase === 'speed') {
      const r =
        progress.speedTotal > 0
          ? Math.min(1, progress.speedTested / progress.speedTotal)
          : 0
      pct = 80 + r * 20
      ratioLabel = t('dash.ratio.speed', { a: num(progress.speedTested), b: num(progress.speedTotal) })
    }
  } else if (isFinished) {
    pct = 100
    ratioLabel =
      phase === 'done'
        ? t('dash.ratio.done')
        : phase === 'stopped'
          ? t('dash.ratio.stopped')
          : t('dash.ratio.error')
  }

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6">
      {/* Title */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
            <AreaChart className="size-4" aria-hidden />
          </span>
          <h2 className="text-base font-bold">{t('dash.title')}</h2>
        </div>
        <span
          className={cn(
            'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium',
            phase === 'error'
              ? 'bg-red-500/10 text-red-500'
              : phase === 'stopped'
                ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                : running
                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                  : 'bg-muted text-muted-foreground'
          )}
        >
          <span
            className={cn(
              'size-1.5 rounded-full',
              running ? 'animate-pulse bg-emerald-500' : 'bg-current opacity-60'
            )}
            aria-hidden
          />
          {t(`phase.${phase}` as DictKey)}
        </span>
      </div>

      {/* Phase stepper */}
      <ol
        className="mt-5 flex items-center justify-between gap-1 sm:gap-2"
        aria-label={t('dash.stepper.aria', { phase: t(`phase.${phase}` as DictKey) })}
      >
        {STEPS.map((step, i) => {
          const Icon = step.icon
          const completed = activeStep > i || (isFinished && phase === 'done')
          const active = i === activeStep && !isFinished
          return (
            <li
              key={step.key}
              className="flex flex-1 flex-col items-center gap-1.5"
              aria-current={active ? 'step' : undefined}
            >
              <div className="flex w-full items-center">
                <div className="flex-1">
                  {i > 0 ? (
                    <div
                      className={cn(
                        'h-0.5 w-full rounded-full transition-colors',
                        i <= activeStep ? 'bg-emerald-500/70' : 'bg-border'
                      )}
                    />
                  ) : null}
                </div>
                <motion.div
                  animate={active ? { scale: [1, 1.12, 1] } : { scale: 1 }}
                  transition={{
                    duration: 1.4,
                    repeat: active ? Infinity : 0,
                    ease: 'easeInOut',
                  }}
                  className={cn(
                    'flex size-9 shrink-0 items-center justify-center rounded-full border-2 transition-colors',
                    completed
                      ? 'border-emerald-500 bg-emerald-500 text-white'
                      : active
                        ? 'border-emerald-500 bg-emerald-500/10 text-emerald-500 dark:text-emerald-400'
                        : 'border-border bg-background/40 text-muted-foreground'
                  )}
                >
                  {completed ? (
                    <CheckCircle2 className="size-4" aria-hidden />
                  ) : (
                    <Icon className="size-4" aria-hidden />
                  )}
                </motion.div>
                <div className="flex-1">
                  {i < STEPS.length - 1 ? (
                    <div
                      className={cn(
                        'h-0.5 w-full rounded-full transition-colors',
                        i + 1 <= activeStep
                          ? 'bg-emerald-500/70'
                          : 'bg-border'
                      )}
                    />
                  ) : null}
                </div>
              </div>
              <span
                className={cn(
                  'text-[10px] font-medium sm:text-[11px]',
                  completed || active
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-muted-foreground'
                )}
              >
                {t(step.labelKey)}
              </span>
            </li>
          )
        })}
      </ol>

      {/* Progress */}
      <div className="mt-5 space-y-2">
        <div className="flex items-center justify-between gap-2 text-xs">
          <span className="font-medium text-muted-foreground">
            {ratioLabel}
          </span>
          <span className="font-mono font-bold tabular-nums" dir="ltr">
            {pct.toFixed(0)}%
          </span>
        </div>
        <div dir="ltr">
          <Progress value={pct} className="h-2" aria-label={t('dash.progress.aria')} />
        </div>
      </div>

      {/* Mini stats */}
      <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        <MiniStat
          label={t('dash.stat.scanned')}
          value={num(progress?.scanned ?? summary?.scanned ?? 0)}
        />
        <MiniStat
          label={t('dash.stat.alive')}
          accent
          value={num(progress?.alive ?? summary?.alive ?? 0)}
        />
        <MiniStat
          label={t('dash.stat.rate')}
          value={num(Math.round(progress?.ipsPerSecond ?? 0))}
        />
        <MiniStat
          label={t('dash.stat.latency')}
          ltr
          value={
            progress?.recentLatency
              ? formatLatency(progress.recentLatency)
              : '—'
          }
        />
        <MiniStat
          label={t('dash.stat.elapsed')}
          ltr
          value={formatDurationHMS(elapsedMs)}
        />
      </div>

      {/* Latency sparkline */}
      <div className="mt-4 rounded-lg border bg-background/40 p-2">
        <div className="mb-1 flex items-center justify-between px-1">
          <span className="text-[10px] font-medium text-muted-foreground">
            {t('dash.spark.title')}
          </span>
          <span className="font-mono text-[10px] text-emerald-500" dir="ltr">
            {latencyHistory.length > 0
              ? formatLatency(latencyHistory[latencyHistory.length - 1].latency)
              : '—'}
          </span>
        </div>
        <div dir="ltr" className="chart-spark h-[60px] w-full">
          {latencyHistory.length > 1 ? (
            <ResponsiveContainer width="100%" height="100%">
              <RechartsAreaChart
                data={latencyHistory}
                margin={{ top: 4, right: 4, bottom: 0, left: 4 }}
              >
                <defs>
                  <linearGradient id="latency-fill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#10b981" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis hide dataKey="t" />
                <YAxis hide width={0} domain={[0, 'auto']} />
                <Tooltip
                  cursor={{ stroke: '#10b981', strokeOpacity: 0.25 }}
                  contentStyle={{
                    background: 'rgba(9,9,11,0.92)',
                    border: '1px solid #27272a',
                    borderRadius: 8,
                    fontSize: 11,
                    fontFamily: 'monospace',
                    color: '#a1a1aa',
                  }}
                  labelFormatter={() => ''}
                  formatter={(value) => [
                    `${Number(value).toFixed(0)} ms`,
                    t('dash.spark.tip'),
                  ]}
                />
                <RechartsArea
                  type="monotone"
                  dataKey="latency"
                  stroke="#10b981"
                  strokeWidth={1.5}
                  fill="url(#latency-fill)"
                  dot={false}
                  activeDot={{
                    r: 3,
                    fill: '#10b981',
                    stroke: 'rgba(16,185,129,0.35)',
                    strokeWidth: 5,
                  }}
                  isAnimationActive={false}
                />
              </RechartsAreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-full items-center justify-center text-[11px] text-muted-foreground">
              {t('dash.spark.empty')}
            </div>
          )}
        </div>
      </div>

      {/* Terminal log */}
      <div className="mt-4 overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950">
        <div
          className="flex items-center gap-1.5 border-b border-zinc-800/80 px-3 py-2"
          dir="ltr"
        >
          <TerminalSquare className="size-3.5 text-zinc-500" aria-hidden />
          <span className="font-mono text-[10px] text-zinc-500">
            scan-engine logs
          </span>
          <span className="ml-auto flex gap-1" aria-hidden>
            <span className="size-2 rounded-full bg-zinc-700" />
            <span className="size-2 rounded-full bg-zinc-700" />
            <span className="size-2 rounded-full bg-emerald-600/70" />
          </span>
        </div>
        <div
          ref={logBoxRef}
          dir="ltr"
          className="scrollbar-thin h-48 overflow-y-auto p-3 font-mono text-xs leading-5"
          role="log"
          aria-live="polite"
          aria-label={t('dash.log.aria')}
        >
          {logs.length === 0 ? (
            <p className="text-zinc-600">
              {'# waiting for scan events… (clean-ip-scanner web)'}
            </p>
          ) : (
            logs.map((l, i) => (
              <div key={`${l.ts}-${i}`} className="flex gap-2">
                <span className="shrink-0 text-zinc-600">
                  [
                  {new Date(l.ts).toLocaleTimeString('en-GB', {
                    hour12: false,
                  })}
                  ]
                </span>
                <span className={cn('break-words', LOG_COLORS[l.level])}>
                  {lang === 'en' && l.messageEn ? l.messageEn : l.message}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
