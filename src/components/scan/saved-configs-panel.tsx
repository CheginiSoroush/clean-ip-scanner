'use client'

/**
 * SavedConfigsPanel — the user's saved VLESS/VMess configs + their subscription.
 *
 * The subscription URL (/api/sub) serves every saved config as a base64 feed
 * that V2rayNG/Hiddify/etc. can import. Rows support per-config copy/delete;
 * the whole store can be wiped with a confirm dialog. Fetch + mutations follow
 * the FavoritesPanel patterns (TanStack Query + sonner toasts).
 */

import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { faIR, enUS } from 'date-fns/locale'
import { toast } from 'sonner'
import {
  Copy,
  KeyRound,
  Link2,
  Loader2,
  RefreshCw,
  ServerOff,
  Trash2,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { fetchJson } from '@/lib/api-types'
import { useI18n } from '@/components/i18n-provider'
import { cn } from '@/lib/utils'
import type { DictKey } from '@/lib/i18n'

interface ConfigItem {
  id: string
  uri: string
  proto: string
  label: string | null
  ip: string | null
  port: number | null
  sni: string | null
  createdAt: string
}

interface ConfigsResponse {
  configs: ConfigItem[]
}

/** proto badge colors — vless emerald / vmess teal (no indigo/blue) */
const PROTO_CLS: Record<string, string> = {
  vless: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  vmess: 'border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400',
}

export function SavedConfigsPanel() {
  const { t, num, lang, dir } = useI18n()
  const qc = useQueryClient()
  // SSR-safe origin read — the panel only mounts after hydration (inactive tabs stay unmounted),
  // the same pattern the share dialog uses
  const subUrl = useMemo(
    () => (typeof window !== 'undefined' ? `${window.location.origin}/api/sub` : ''),
    [],
  )

  const list = useQuery<ConfigsResponse>({
    queryKey: ['saved-configs'],
    queryFn: () => fetchJson<ConfigsResponse>('/api/configs'),
    retry: false,
  })

  const configs = list.data?.configs ?? []
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['saved-configs'] })
  }

  const copyText = async (text: string, okKey: DictKey, vars?: Record<string, string | number>) => {
    try {
      await navigator.clipboard.writeText(text)
      toast.success(t(okKey, vars))
    } catch {
      toast.error(t('configs.toast.copy.fail'))
    }
  }

  const removeOne = useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`/api/configs?id=${encodeURIComponent(id)}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('HTTP error')
      return (await res.json()) as { remaining: number }
    },
    onSuccess: () => {
      toast.success(t('configs.toast.deleted'))
      invalidate()
    },
    onError: () => toast.error(t('configs.toast.delete.fail')),
  })

  const removeAll = useMutation({
    mutationFn: async (count: number) => {
      const res = await fetch('/api/configs?all=1', { method: 'DELETE' })
      if (!res.ok) throw new Error('HTTP error')
      return (await res.json()) as { remaining: number }
    },
    onSuccess: (_d, count) => {
      toast.success(t('configs.toast.deleted.all', { n: num(count) }))
      invalidate()
    },
    onError: () => toast.error(t('configs.toast.delete.fail')),
  })

  const dateFnsLocale = lang === 'fa' ? faIR : enUS

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6">
      {/* ---------- header ---------- */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-lg bg-teal-500/10 text-teal-600 dark:text-teal-400">
            <KeyRound className="size-4" aria-hidden />
          </span>
          <h2 className="text-base font-bold">{t('configs.title')}</h2>
          {configs.length > 0 ? (
            <Badge variant="outline" className="text-muted-foreground">
              {t('configs.count', { n: num(configs.length) })}
            </Badge>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {configs.length > 0 ? (
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-9 gap-1.5 border-red-500/30 text-red-600 hover:bg-red-500/10 hover:text-red-700 dark:text-red-400"
                  disabled={removeAll.isPending}
                >
                  <Trash2 className="size-3.5" aria-hidden />
                  {t('configs.delete.all')}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent dir={dir}>
                <AlertDialogHeader>
                  <AlertDialogTitle>{t('configs.delete.all.title')}</AlertDialogTitle>
                  <AlertDialogDescription>{t('configs.delete.all.desc')}</AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>{t('configs.cancel')}</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => removeAll.mutate(configs.length)}
                    className="bg-destructive text-white hover:bg-destructive/90"
                  >
                    {t('configs.delete.confirm')}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          ) : null}
          <Button
            variant="outline"
            size="icon"
            className="size-9"
            onClick={() => list.refetch()}
            disabled={list.isFetching}
            aria-label={t('configs.refresh.aria')}
          >
            <RefreshCw className={cn('size-3.5', list.isFetching && 'animate-spin')} aria-hidden />
          </Button>
        </div>
      </div>

      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{t('configs.desc')}</p>

      {/* ---------- subscription URL box ---------- */}
      <div className="mt-3 rounded-lg border bg-background/40 p-3" role="group" aria-label={t('sub.url')}>
        <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
          <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <Link2 className="size-3.5 text-teal-500" aria-hidden />
            {t('sub.url')}
          </p>
          {configs.length > 0 ? (
            <Badge
              variant="outline"
              className="border-teal-500/30 bg-teal-500/10 px-1.5 py-0 text-[10px] text-teal-600 dark:text-teal-400"
              aria-live="polite"
            >
              {t('configs.count', { n: num(configs.length) })}
            </Badge>
          ) : null}
        </div>
        <div className="flex items-center gap-1.5">
          <Input
            value={subUrl}
            readOnly
            dir="ltr"
            placeholder="…"
            aria-label={t('sub.aria')}
            spellCheck={false}
            className="h-11 min-w-0 flex-1 font-mono text-xs sm:h-9"
          />
          <Button
            variant="outline"
            size="sm"
            className="h-11 shrink-0 gap-1 border-teal-500/30 px-3 text-[11px] text-teal-700 hover:bg-teal-500/10 dark:text-teal-400 sm:h-9"
            onClick={() => void copyText(subUrl, 'sub.copy.ok')}
            disabled={!subUrl}
          >
            <Copy className="size-3" aria-hidden />
            {t('sub.copy')}
          </Button>
        </div>
        <p className="mt-1.5 text-[10px] text-muted-foreground">{t('sub.hint')}</p>
      </div>

      {/* ---------- error ---------- */}
      {list.isError ? (
        <div className="mt-5 flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-red-500/30 bg-red-500/5 py-10 text-center">
          <ServerOff className="size-7 text-red-400" aria-hidden />
          <p className="text-sm font-semibold">{t('configs.error.title')}</p>
          <Button variant="outline" size="sm" onClick={() => list.refetch()} className="h-9">
            {t('configs.retry')}
          </Button>
        </div>
      ) : null}

      {/* ---------- loading skeleton ---------- */}
      {!list.isError && list.isLoading ? (
        <div className="mt-5 space-y-2">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-11 w-full rounded-lg" />
          ))}
        </div>
      ) : null}

      {/* ---------- empty ---------- */}
      {!list.isError && !list.isLoading && configs.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-14 text-center">
          <span className="flex size-16 items-center justify-center rounded-full border border-dashed border-border bg-background/40">
            <KeyRound className="size-7 text-muted-foreground" aria-hidden />
          </span>
          <div>
            <p className="text-sm font-semibold">{t('configs.empty.title')}</p>
            <p className="mx-auto mt-1 max-w-xs text-xs text-muted-foreground">
              {t('configs.empty.sub')}
            </p>
          </div>
        </div>
      ) : null}

      {/* ---------- list ---------- */}
      {configs.length > 0 ? (
        <ul
          className="scrollbar-thin mt-4 max-h-96 space-y-1.5 overflow-y-auto"
          aria-label={t('configs.title')}
        >
          {configs.map((c) => {
            const addr = c.ip ? `${c.ip}${c.port ? `:${c.port}` : ''}` : null
            return (
              <li
                key={c.id}
                className="flex items-center justify-between gap-2 rounded-lg border bg-background/50 px-2.5 py-1.5"
              >
                <div className="min-w-0">
                  <div className="flex min-w-0 items-center gap-1.5">
                    <Badge
                      variant="outline"
                      className={cn('shrink-0 px-1 text-[8px]', PROTO_CLS[c.proto] ?? 'border-border')}
                      dir="ltr"
                    >
                      {c.proto}
                    </Badge>
                    {addr ? (
                      <span className="shrink-0 font-mono text-[10px] text-muted-foreground" dir="ltr">
                        {addr}
                      </span>
                    ) : null}
                    {c.label ? (
                      <span className="truncate text-[10px] text-muted-foreground">{c.label}</span>
                    ) : null}
                    <span className="ms-auto hidden shrink-0 whitespace-nowrap text-[10px] text-muted-foreground/70 sm:inline">
                      {formatDistanceToNow(new Date(c.createdAt), {
                        addSuffix: true,
                        locale: dateFnsLocale,
                      })}
                    </span>
                  </div>
                  <p className="mt-0.5 truncate font-mono text-[11px]" dir="ltr" title={c.uri}>
                    {c.uri}
                  </p>
                  {c.sni ? (
                    <p className="truncate text-[10px] text-muted-foreground/80" dir="ltr">
                      SNI: {c.sni}
                    </p>
                  ) : null}
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <TooltipProvider delayDuration={120}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <button
                          type="button"
                          onClick={() => void copyText(c.uri, 'configs.toast.copy.ok')}
                          aria-label={t('configs.copy.aria', { ep: addr ?? c.id })}
                          className="inline-flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-teal-500/10 hover:text-teal-600 dark:hover:text-teal-400"
                        >
                          <Copy className="size-3.5" aria-hidden />
                        </button>
                      </TooltipTrigger>
                      <TooltipContent dir={dir} className="text-[10px]">
                        {t('configs.copy.aria', { ep: addr ?? c.id })}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-8 text-red-500 hover:text-red-600"
                        aria-label={t('configs.delete.aria', { ep: addr ?? c.id })}
                      >
                        <Trash2 className="size-3.5" aria-hidden />
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent dir={dir}>
                      <AlertDialogHeader>
                        <AlertDialogTitle>{t('configs.delete.title')}</AlertDialogTitle>
                        <AlertDialogDescription>
                          {t('configs.delete.desc')}
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>{t('configs.cancel')}</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => removeOne.mutate(c.id)}
                          className="bg-destructive text-white hover:bg-destructive/90"
                        >
                          {t('configs.delete.confirm')}
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              </li>
            )
          })}
        </ul>
      ) : null}

      {/* mutation-in-flight spinner */}
      {(removeOne.isPending || removeAll.isPending) && (
        <div className="mt-2 flex justify-center">
          <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden />
        </div>
      )}
    </div>
  )
}
