'use client'

import { useQuery } from '@tanstack/react-query'
import { Activity, Globe, ShieldCheck, Trophy } from 'lucide-react'
import { fetchJson, type StatsResponse } from '@/lib/api-types'
import { formatBytesPerSec, formatLatency } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import { useCountUp } from '@/hooks/use-count-up'
import { cn } from '@/lib/utils'

interface StatsCardDef {
  title: string
  icon: React.ReactNode
  accent: string
  main: React.ReactNode
  sub?: React.ReactNode
}

/** Animated integer display (locale digits). */
function AnimatedNumber({ value }: { value: number }) {
  const { num } = useI18n()
  const v = useCountUp(value)
  return <span dir="ltr">{num(v)}</span>
}

export function StatsStrip() {
  const { t } = useI18n()
  const { data, isLoading, isError } = useQuery<StatsResponse>({
    queryKey: ['stats'],
    queryFn: () => fetchJson<StatsResponse>('/api/stats'),
    // graceful: never spam retries while backend is unavailable
    retry: false,
    refetchInterval: 30_000,
  })

  const zero = isLoading || isError

  const cards: StatsCardDef[] = [
    {
      title: t('stats.scans.title'),
      icon: <Activity className="size-4" aria-hidden />,
      accent: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
      main: zero ? <span dir="ltr">—</span> : <AnimatedNumber value={data?.totalScans ?? 0} />,
      sub: t('stats.scans.sub'),
    },
    {
      title: t('stats.ips.title'),
      icon: <Globe className="size-4" aria-hidden />,
      accent: 'bg-teal-500/10 text-teal-600 dark:text-teal-400',
      main: zero ? <span dir="ltr">—</span> : <AnimatedNumber value={data?.totalIPsScanned ?? 0} />,
      sub: t('stats.ips.sub'),
    },
    {
      title: t('stats.clean.title'),
      icon: <ShieldCheck className="size-4" aria-hidden />,
      accent: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
      main: zero ? <span dir="ltr">—</span> : <AnimatedNumber value={data?.totalCleanIPs ?? 0} />,
      sub: t('stats.clean.sub'),
    },
    {
      title: t('stats.best.title'),
      icon: <Trophy className="size-4" aria-hidden />,
      accent: 'bg-orange-500/10 text-orange-600 dark:text-orange-400',
      main: (
        <span className="font-mono text-sm font-semibold" dir="ltr">
          {data?.bestIp?.ip ?? '—'}
        </span>
      ),
      sub: data?.bestIp ? (
        <span className="font-mono" dir="ltr">
          {formatLatency(data.bestIp.latencyMs)} ·{' '}
          {formatBytesPerSec(data.bestIp.totalSpeed)}
        </span>
      ) : (
        t('stats.best.sub.none')
      ),
    },
  ]

  return (
    <section
      aria-label={t('stats.aria')}
      className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4"
    >
      {cards.map((c) => (
        <div
          key={c.title}
          className="group relative overflow-hidden rounded-xl border bg-card/60 p-4 backdrop-blur transition-all hover:-translate-y-0.5 hover:border-emerald-500/30 hover:shadow-[0_8px_24px_-12px_rgba(16,185,129,0.25)]"
        >
          <span
            aria-hidden
            className="absolute -top-10 -end-10 size-20 rounded-full bg-emerald-500/5 blur-2xl transition-opacity group-hover:bg-emerald-500/10"
          />
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-muted-foreground">
              {c.title}
            </span>
            <span
              className={cn(
                'flex size-8 items-center justify-center rounded-lg transition-transform group-hover:scale-110',
                c.accent
              )}
            >
              {c.icon}
            </span>
          </div>
          <div
            className={cn(
              'mt-2 text-lg font-bold tracking-tight sm:text-xl',
              isLoading && 'animate-pulse text-muted-foreground'
            )}
          >
            {c.main}
          </div>
          <div className="mt-0.5 truncate text-[11px] text-muted-foreground">
            {c.sub}
          </div>
        </div>
      ))}
    </section>
  )
}
