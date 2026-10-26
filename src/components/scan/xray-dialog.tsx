'use client'

/**
 * XrayDialog — Xray-style connectivity probe + ready-to-paste proxy configs.
 *
 * Probe: asks the scan engine to do a REAL TLS handshake against the raw IP
 * with the chosen SNI (what a proxy core does through a CDN) and reports
 * timings, TLS/cipher/ALPN, the leaf certificate (CN/issuer/expiry/SAN match)
 * and an HTTP status — then grades the IP.
 *
 * Config: generates VLESS / VMess / Trojan outbounds (ws|tcp + TLS) plus the
 * standard share links, ready to paste into Xray/V2Ray clients.
 *
 * v6.7 — saved generator presets: a collapsible strip at the top of the dialog
 * backed by GET/POST/DELETE /api/xray-presets (the API is the source of truth,
 * nothing is persisted in localStorage). Applying a preset fills host/protocol/
 * transport/wsPath ONLY — the port is prop-driven by the scan target.
 */

import { useEffect, useMemo, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  BadgeCheck,
  BadgeX,
  BookmarkPlus,
  Check,
  ChevronDown,
  Copy,
  Download,
  Gauge,
  Loader2,
  RefreshCw,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { useI18n } from '@/components/i18n-provider'
import { cn } from '@/lib/utils'
import type { LiveResult, XrayPreset, XrayProbeResult } from '@/lib/scan-protocol'
import { XRAY_PRESETS_CAP } from '@/lib/scan-protocol'
import {
  buildFullConfig,
  buildShareLink,
  probeHostFor,
  type XrayProtocol,
  type XrayTransport,
} from '@/lib/xray-config'

interface XrayDialogProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  /** the clean-IP row the dialog was opened for */
  target: LiveResult | null
  /** TCP port of the scan the IP came from (the port configs will use) */
  port: number
  /** CDN preset id — picks a sensible default SNI host */
  preset?: string
  connected: boolean
  onProbe: (payload: { ip: string; port: number; host: string }) => Promise<XrayProbeResult | null>
}

const GRADE_STYLE: Record<string, string> = {
  excellent: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  good: 'border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400',
  weak: 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  fail: 'border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400',
}

function TimingBar({
  label,
  ms,
  max,
  color,
}: {
  label: string
  ms?: number
  max: number
  color: string
}) {
  const width = ms && max > 0 ? Math.max(4, Math.min(100, (ms / max) * 100)) : 0
  return (
    <div className="flex items-center gap-2">
      <span className="w-10 shrink-0 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
        {width > 0 ? (
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${width}%` }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
            className={cn('h-full rounded-full', color)}
          />
        ) : (
          <div className="h-full w-full rounded-full border border-dashed border-border/60" />
        )}
      </div>
      <span dir="ltr" className="w-14 shrink-0 text-end font-mono text-[10.5px] tabular-nums">
        {ms != null ? `${ms.toFixed(0)} ms` : '—'}
      </span>
    </div>
  )
}

export function XrayDialog({ open, onOpenChange, target, port, preset, connected, onProbe }: XrayDialogProps) {
  const { t, num, dir } = useI18n()
  const [host, setHost] = useState('')
  const [probing, setProbing] = useState(false)
  const [probe, setProbe] = useState<XrayProbeResult | null>(null)
  const [protocol, setProtocol] = useState<XrayProtocol>('vless')
  const [transport, setTransport] = useState<XrayTransport>('ws')
  const [wsPath, setWsPath] = useState('/ws')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  // v6.7 — presets strip
  const [presetsOpen, setPresetsOpen] = useState(true)
  const [presetName, setPresetName] = useState('')
  /** name of the last applied preset — drives the honest "port comes from the target" note */
  const [appliedPreset, setAppliedPreset] = useState<string | null>(null)
  /** inline save hint (client validation + mapped 400 codes) */
  const [saveHint, setSaveHint] = useState<string | null>(null)
  /** id of the preset whose DELETE is in flight (spinner on the chip) */
  const [deletingId, setDeletingId] = useState<string | null>(null)

  // reset per-target when the dialog opens for another IP
  useEffect(() => {
    if (open && target) {
      setHost(probeHostFor(preset))
      setProbe(null)
      setProbing(false)
      setAppliedPreset(null)
      setSaveHint(null)
    }
  }, [open, target, preset])

  // ---------- v6.7 — presets (API is the source of truth; fetched only while the dialog is open) ----------
  const qc = useQueryClient()
  const presetsQ = useQuery<XrayPreset[]>({
    queryKey: ['xray-presets'],
    queryFn: async () => {
      const res = await fetch('/api/xray-presets')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = (await res.json().catch(() => null)) as unknown
      // defensive shape: bare array or { presets: [...] }
      if (Array.isArray(data)) return data as XrayPreset[]
      if (data && typeof data === 'object' && Array.isArray((data as { presets?: unknown }).presets)) {
        return (data as { presets: XrayPreset[] }).presets
      }
      return []
    },
    enabled: open,
    retry: false,
    staleTime: 30_000,
  })
  const presets = useMemo(() => presetsQ.data ?? [], [presetsQ.data])

  /** apply = fill host/protocol/transport/wsPath ONLY (the port is prop-driven — see the port note) */
  const applyPreset = (p: XrayPreset) => {
    setHost(p.host)
    setProtocol(p.protocol)
    setTransport(p.transport)
    setWsPath(p.wsPath)
    setAppliedPreset(p.name)
    toast.success(t('xp.apply.ok', { name: p.name }))
  }

  const savePreset = useMutation({
    mutationFn: async () => {
      const res = await fetch('/api/xray-presets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: presetName.trim(),
          host: host.trim() || probeHostFor(preset),
          // the dialog cannot change the port — record the CURRENT target port so the preset stays usable
          port: port || 443,
          protocol,
          transport,
          wsPath,
        }),
      })
      const data = (await res.json().catch(() => null)) as { error?: string; field?: string } | null
      if (res.status === 400) {
        const err = new Error(data?.error ?? 'invalid_preset') as Error & { code?: string }
        err.code = data?.error ?? 'invalid_preset'
        throw err
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return true
    },
    onSuccess: () => {
      toast.success(t('xp.save.ok', { name: presetName.trim() }))
      setPresetName('')
      setSaveHint(null)
      void qc.invalidateQueries({ queryKey: ['xray-presets'] })
    },
    onError: (e) => {
      const code = (e as Error & { code?: string }).code
      const msg =
        code === 'duplicate_preset'
          ? t('xp.dup')
          : code === 'preset_limit'
            ? t('xp.limit', { n: num(XRAY_PRESETS_CAP) })
            : code === 'invalid_preset'
              ? t('xp.invalid')
              : t('xp.save.fail')
      setSaveHint(msg)
      toast.error(msg)
    },
  })

  /** client-side guard before the POST: name required (≤40 enforced by maxLength), ws path only for ws transport */
  const canSubmitPreset = presetName.trim().length > 0 && (transport === 'tcp' || (wsPath.startsWith('/') && wsPath.length <= 64))

  const submitPreset = () => {
    if (savePreset.isPending) return
    if (!canSubmitPreset) {
      setSaveHint(t('xp.invalid'))
      return
    }
    savePreset.mutate()
  }

  const delPreset = useMutation({
    mutationFn: async ({ id }: { id: string; name: string }) => {
      const res = await fetch(`/api/xray-presets?id=${encodeURIComponent(id)}`, { method: 'DELETE' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return id
    },
    onMutate: ({ id }) => setDeletingId(id),
    onSuccess: (_id, vars) => {
      toast.success(t('xp.delete.ok', { name: vars.name }))
      void qc.invalidateQueries({ queryKey: ['xray-presets'] })
    },
    onError: () => toast.error(t('xp.delete.fail')),
    onSettled: () => setDeletingId(null),
  })

  const cfgInput = useMemo(
    () => ({
      ip: target?.ip ?? '',
      port: port || 443,
      host: host.trim() || probeHostFor(preset),
      protocol,
      transport,
      path: wsPath,
      remark: `Clean ${target?.ip ?? ''}`,
    }),
    [target, port, host, preset, protocol, transport, wsPath],
  )

  const configJson = useMemo(
    () => (target ? buildFullConfig(cfgInput) : ''),
    [target, cfgInput],
  )
  const shareLink = useMemo(
    () => (target ? buildShareLink(cfgInput) : ''),
    [target, cfgInput],
  )

  const copyText = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedKey(key)
      toast.success(t('xray.toast.copied'))
      window.setTimeout(() => setCopiedKey(null), 1600)
    } catch {
      toast.error(t('xray.toast.copyfail'))
    }
  }

  const downloadConfig = () => {
    if (!target) return
    const blob = new Blob([configJson], { type: 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `xray-${target.ip.replace(/[:.]/g, '-')}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    toast.success(t('xray.toast.download'))
  }

  const runProbe = async () => {
    if (!target || probing || !connected) return
    setProbing(true)
    setProbe(null)
    try {
      const r = await onProbe({ ip: target.ip, port: cfgInput.port, host: cfgInput.host })
      if (r) setProbe(r)
      else toast.error(t('xray.toast.offline'))
    } finally {
      setProbing(false)
    }
  }

  const gradeLabel = (g?: string) =>
    g ? t(`xray.grade.${g}` as Parameters<typeof t>[0]) : ''
  const maxTiming = Math.max(probe?.tcpMs ?? 0, probe?.tlsMs ?? 0, probe?.httpMs ?? 0, 1)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        dir={dir}
        className="grid-cols-[minmax(0,1fr)] max-h-[90vh] overflow-y-auto overflow-x-hidden sm:max-w-2xl"
      >
        <DialogHeader>
          <DialogTitle className="flex flex-wrap items-center gap-2">
            <span className="flex size-8 items-center justify-center rounded-lg bg-teal-500/10 text-teal-600 dark:text-teal-400">
              <Zap className="size-4" aria-hidden />
            </span>
            <span>{t('xray.title')}</span>
            {target ? (
              <span dir="ltr" className="font-mono text-sm font-bold text-emerald-600 dark:text-emerald-400">
                {target.ip}:{port || 443}
              </span>
            ) : null}
          </DialogTitle>
          <DialogDescription>{t('xray.desc')}</DialogDescription>
        </DialogHeader>

        {target ? (
          <div className="space-y-4">
            {/* ---------- v6.7 — saved generator presets (collapsible strip, API-backed) ---------- */}
            <div className="rounded-xl border border-zinc-500/30 bg-zinc-500/5">
              <button
                type="button"
                aria-expanded={presetsOpen}
                onClick={() => setPresetsOpen((v) => !v)}
                className="flex min-h-11 w-full items-center justify-between gap-2 px-3 py-2 text-start transition-colors hover:bg-zinc-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-500/60"
              >
                <span className="flex items-center gap-1.5 text-[11px] font-semibold text-zinc-700 dark:text-zinc-300">
                  <BookmarkPlus className="size-3.5 text-zinc-500" aria-hidden />
                  {t('xp.title')}
                  <span
                    className="rounded-md border border-zinc-500/40 bg-background/60 px-1 py-0 font-mono text-[10px] text-zinc-600 dark:text-zinc-300"
                    dir="ltr"
                  >
                    {num(presets.length)}
                  </span>
                </span>
                <ChevronDown
                  className={cn('size-3.5 shrink-0 text-zinc-500 transition-transform', presetsOpen && 'rotate-180')}
                  aria-hidden
                />
              </button>

              {presetsOpen ? (
                <div className="space-y-2.5 border-t border-zinc-500/20 px-3 py-3">
                  <p className="text-[10px] leading-relaxed text-muted-foreground">{t('xp.hint')}</p>

                  {/* honest load error (routes may still be landing / engine offline) */}
                  {presetsQ.isError ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <p role="alert" className="text-[10.5px] text-amber-600 dark:text-amber-400">
                        {t('xp.load.fail')}
                      </p>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-11 gap-1 border-zinc-500/40 px-2 text-[10.5px] text-zinc-600 hover:bg-zinc-500/10 hover:text-zinc-800 dark:text-zinc-300 sm:h-7"
                        onClick={() => void presetsQ.refetch()}
                        aria-label={t('xp.retry')}
                      >
                        <RefreshCw className="size-3" aria-hidden />
                        {t('xp.retry')}
                      </Button>
                    </div>
                  ) : null}

                  {/* preset chips — name bold + mono protocol/transport sub-label */}
                  {presets.length > 0 ? (
                    <div className="flex flex-wrap items-stretch gap-1.5" role="group" aria-label={t('xp.title')}>
                      {presets.map((p) => (
                        <div
                          key={p.id}
                          className="flex max-w-56 items-stretch overflow-hidden rounded-lg border border-border bg-background/50 transition-colors focus-within:ring-2 focus-within:ring-teal-500/50"
                        >
                          <button
                            type="button"
                            onClick={() => applyPreset(p)}
                            aria-label={t('xp.apply.aria', { name: p.name })}
                            className="min-h-11 min-w-0 flex-1 px-2.5 py-1.5 text-start transition-colors hover:bg-teal-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-teal-500/60"
                          >
                            <span className="block truncate text-[11px] font-bold">{p.name}</span>
                            <span dir="ltr" className="block font-mono text-[9.5px] text-muted-foreground">
                              {p.protocol}/{p.transport}
                            </span>
                          </button>
                          <button
                            type="button"
                            onClick={() => delPreset.mutate({ id: p.id, name: p.name })}
                            aria-label={t('xp.delete.aria', { name: p.name })}
                            disabled={deletingId != null}
                            className="flex w-8 shrink-0 items-center justify-center text-muted-foreground/70 transition-colors hover:bg-red-500/10 hover:text-red-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-red-500/60 disabled:cursor-not-allowed disabled:opacity-50 dark:hover:text-red-400"
                          >
                            {deletingId === p.id ? (
                              <Loader2 className="size-3 animate-spin" aria-hidden />
                            ) : (
                              <X className="size-3" aria-hidden />
                            )}
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : !presetsQ.isError && !presetsQ.isLoading ? (
                    <p className="rounded-lg border border-dashed border-border bg-background/40 px-3 py-3 text-center text-[10.5px] text-muted-foreground">
                      {t('xp.empty')}
                    </p>
                  ) : null}

                  {/* honest note after applying — the dialog cannot change the port (prop-driven) */}
                  {appliedPreset ? (
                    <p className="text-[10px] text-muted-foreground" aria-live="polite">
                      {t('xp.port.note', { port: num(port || 443) })}
                    </p>
                  ) : null}

                  {/* save current host/protocol/transport/wsPath as a named preset */}
                  <div className="flex flex-col gap-2 sm:flex-row">
                    <Input
                      value={presetName}
                      onChange={(e) => {
                        setPresetName(e.target.value)
                        if (saveHint) setSaveHint(null)
                      }}
                      maxLength={40}
                      placeholder={t('xp.name.ph')}
                      aria-label={t('xp.name.ph')}
                      className="h-11 flex-1 text-xs sm:h-9"
                      spellCheck={false}
                      autoComplete="off"
                    />
                    <Button
                      type="button"
                      size="sm"
                      onClick={submitPreset}
                      disabled={savePreset.isPending || presetName.trim() === ''}
                      className="h-11 gap-1.5 bg-teal-600 text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-600 sm:h-9"
                    >
                      {savePreset.isPending ? (
                        <Loader2 className="size-3.5 animate-spin" aria-hidden />
                      ) : (
                        <BookmarkPlus className="size-3.5" aria-hidden />
                      )}
                      {t('xp.save')}
                    </Button>
                  </div>
                  {saveHint ? (
                    <p role="alert" className="text-[10px] text-amber-600 dark:text-amber-400">
                      {saveHint}
                    </p>
                  ) : null}
                </div>
              ) : null}
            </div>

            {/* SNI host input + probe trigger */}
            <div className="rounded-xl border bg-background/40 p-3">
              <label className="text-xs font-semibold" htmlFor="xray-host">
                {t('xray.host.label')}
              </label>
              <div className="mt-1.5 flex flex-col gap-2 sm:flex-row">
                <Input
                  id="xray-host"
                  value={host}
                  onChange={(e) => setHost(e.target.value.replace(/\s+/g, ''))}
                  dir="ltr"
                  placeholder="speed.cloudflare.com"
                  className="h-9 flex-1 font-mono text-xs"
                  spellCheck={false}
                  autoComplete="off"
                />
                <Button
                  type="button"
                  size="sm"
                  onClick={runProbe}
                  disabled={probing || !connected || !host.trim()}
                  className="h-9 gap-1.5 bg-teal-600 text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-600"
                >
                  {probing ? (
                    <Loader2 className="size-3.5 animate-spin" aria-hidden />
                  ) : (
                    <Zap className="size-3.5" aria-hidden />
                  )}
                  {probing ? t('xray.probing') : t('xray.probe')}
                </Button>
              </div>
              <p className="mt-1.5 text-[10.5px] leading-4 text-muted-foreground">{t('xray.host.hint')}</p>
            </div>

            {/* probe result */}
            <AnimatePresence mode="wait">
              {probe ? (
                <motion.div
                  key={`${probe.ip}-${probe.totalMs}`}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                  transition={{ duration: 0.25 }}
                  className="space-y-3 rounded-xl border bg-background/40 p-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold">{t('xray.result.title')}</span>
                      {probe.ok ? (
                        <Badge variant="outline" className={cn('px-2 py-0.5 text-[10px] font-bold uppercase', GRADE_STYLE[probe.grade ?? 'fail'])}>
                          {gradeLabel(probe.grade)}
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[10px] font-bold text-red-600 dark:text-red-400">
                          {t('xray.grade.fail')}
                        </Badge>
                      )}
                    </div>
                    {probe.ok ? (
                      <span dir="ltr" className="font-mono text-[10.5px] text-muted-foreground">
                        {t('xray.result.total')} {probe.totalMs?.toFixed(0) ?? '—'} ms
                      </span>
                    ) : null}
                  </div>

                  {probe.ok ? (
                    <>
                      {/* timing bars */}
                      <div className="space-y-1.5">
                        <TimingBar label="TCP" ms={probe.tcpMs} max={maxTiming} color="bg-zinc-400/80 dark:bg-zinc-500" />
                        <TimingBar label="TLS" ms={probe.tlsMs} max={maxTiming} color="bg-teal-500/80" />
                        <TimingBar label="HTTP" ms={probe.httpMs} max={maxTiming} color="bg-emerald-500/80" />
                      </div>

                      {/* TLS + http chips */}
                      <div className="flex flex-wrap gap-1.5">
                        {[
                          probe.tlsVersion ? `TLS ${probe.tlsVersion.replace('TLS', '').trim()}` : null,
                          probe.cipher,
                          probe.alpn ? `ALPN ${probe.alpn}` : null,
                          probe.httpStatus != null ? `HTTP ${probe.httpStatus}` : null,
                        ]
                          .filter(Boolean)
                          .map((chip) => (
                            <span
                              key={chip!}
                              dir="ltr"
                              className="rounded-md border bg-muted/50 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                            >
                              {chip}
                            </span>
                          ))}
                      </div>

                      {/* certificate card */}
                      <div className="rounded-lg border border-dashed p-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="flex items-center gap-1.5 text-[11px] font-semibold">
                            <ShieldCheck className="size-3.5 text-teal-600 dark:text-teal-400" aria-hidden />
                            {t('xray.cert.title')}
                          </span>
                          {probe.cert?.matched ? (
                            <Badge variant="outline" className="gap-1 border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0 text-[10px] text-emerald-600 dark:text-emerald-400">
                              <BadgeCheck className="size-3" aria-hidden />
                              {t('xray.cert.sni.ok')}
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="gap-1 border-amber-500/40 bg-amber-500/10 px-1.5 py-0 text-[10px] text-amber-600 dark:text-amber-400">
                              <BadgeX className="size-3" aria-hidden />
                              {t('xray.cert.sni.no')}
                            </Badge>
                          )}
                        </div>
                        {probe.cert?.subjectCN || probe.cert?.validTo ? (
                          <div dir="ltr" className="mt-2 grid grid-cols-1 gap-x-4 gap-y-1 text-[10.5px] sm:grid-cols-2">
                            <span className="flex justify-between gap-2 sm:block">
                              <span className="text-muted-foreground">CN </span>
                              <span className="font-mono">{probe.cert?.subjectCN ?? '—'}</span>
                            </span>
                            <span className="flex justify-between gap-2 sm:block">
                              <span className="text-muted-foreground">Issuer </span>
                              <span className="font-mono">{probe.cert?.issuer ?? '—'}</span>
                            </span>
                            <span className="flex justify-between gap-2 sm:block">
                              <span className="text-muted-foreground">Expires </span>
                              <span className="font-mono">{probe.cert?.validTo?.slice(0, 10) ?? '—'}</span>
                            </span>
                            <span className="flex justify-between gap-2 sm:block">
                              <span className="text-muted-foreground">{t('xray.cert.left')} </span>
                              <span className="font-mono">
                                {probe.cert?.daysLeft != null ? t('xray.cert.days', { n: num(probe.cert.daysLeft) }) : '—'}
                              </span>
                            </span>
                          </div>
                        ) : (
                          <p className="mt-2 text-[10.5px] leading-4 text-muted-foreground">{t('xray.cert.none')}</p>
                        )}
                      </div>
                    </>
                  ) : (
                    <p dir="ltr" className="rounded-lg bg-red-500/5 p-2.5 font-mono text-[11px] text-red-600 dark:text-red-400">
                      {probe.error ?? 'probe failed'}
                    </p>
                  )}
                </motion.div>
              ) : probing ? (
                <motion.div
                  key="probing"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center justify-center gap-2 rounded-xl border border-dashed py-6 text-xs text-muted-foreground"
                >
                  <Loader2 className="size-4 animate-spin text-teal-500" aria-hidden />
                  {t('xray.probing.sub')}
                </motion.div>
              ) : null}
            </AnimatePresence>

            {/* config generator */}
            <div className="rounded-xl border bg-background/40 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="flex items-center gap-1.5 text-xs font-semibold">
                  <Gauge className="size-3.5 text-teal-600 dark:text-teal-400" aria-hidden />
                  {t('xray.config.title')}
                </span>
                <div className="flex items-center gap-2">
                  <Tabs dir={dir} value={protocol} onValueChange={(v) => setProtocol(v as XrayProtocol)}>
                    <TabsList className="h-7 p-0.5">
                      {(['vless', 'vmess', 'trojan'] as const).map((p) => (
                        <TabsTrigger key={p} value={p} className="h-6 px-2 font-mono text-[10.5px]">
                          {p}
                        </TabsTrigger>
                      ))}
                    </TabsList>
                  </Tabs>
                  <Tabs dir={dir} value={transport} onValueChange={(v) => setTransport(v as XrayTransport)}>
                    <TabsList className="h-7 p-0.5">
                      {(['ws', 'tcp'] as const).map((p) => (
                        <TabsTrigger key={p} value={p} className="h-6 px-2 font-mono text-[10.5px] uppercase">
                          {p}
                        </TabsTrigger>
                      ))}
                    </TabsList>
                  </Tabs>
                </div>
              </div>

              {transport === 'ws' ? (
                <div className="mt-2 flex items-center gap-2">
                  <label className="shrink-0 text-[10.5px] font-semibold text-muted-foreground" htmlFor="xray-path">
                    {t('xray.path.label')}
                  </label>
                  <Input
                    id="xray-path"
                    value={wsPath}
                    onChange={(e) => setWsPath(e.target.value)}
                    dir="ltr"
                    className="h-8 flex-1 font-mono text-xs"
                    placeholder="/ws"
                    spellCheck={false}
                  />
                </div>
              ) : null}

              <pre
                dir="ltr"
                className="scrollbar-thin mt-2 max-h-56 overflow-auto rounded-lg border bg-zinc-950 p-3 font-mono text-[10.5px] leading-relaxed text-zinc-200"
              >
                {configJson}
              </pre>

              {/* actions */}
              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                <TooltipProvider delayDuration={200}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-8 gap-1.5"
                        onClick={() => copyText(configJson, 'json')}
                      >
                        {copiedKey === 'json' ? (
                          <Check className="size-3.5 text-emerald-500" aria-hidden />
                        ) : (
                          <Copy className="size-3.5" aria-hidden />
                        )}
                        {t('xray.config.copy')}
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent dir={dir}>
                      <p>{t('xray.config.copy.hint')}</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-8 gap-1.5"
                  onClick={downloadConfig}
                >
                  <Download className="size-3.5" aria-hidden />
                  {t('xray.config.download')}
                </Button>
                <Badge variant="outline" className="ms-auto gap-1 border-teal-500/30 bg-teal-500/5 px-1.5 py-0 text-[10px] text-teal-600 dark:text-teal-400">
                  <Activity className="size-3" aria-hidden />
                  {t('xray.config.outbound')}
                </Badge>
              </div>

              {/* share link */}
              <div className="mt-2.5">
                <span className="text-[10.5px] font-semibold text-muted-foreground">{t('xray.link.label')}</span>
                <div className="mt-1 flex items-center gap-2">
                  <code
                    dir="ltr"
                    className="scrollbar-thin flex-1 overflow-x-auto whitespace-nowrap rounded-lg border bg-muted/40 px-2 py-1.5 font-mono text-[10px] text-muted-foreground"
                  >
                    {shareLink}
                  </code>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-8 shrink-0 gap-1 px-2"
                    onClick={() => copyText(shareLink, 'link')}
                    aria-label={t('xray.link.copy.aria')}
                  >
                    {copiedKey === 'link' ? (
                      <Check className="size-3.5 text-emerald-500" aria-hidden />
                    ) : (
                      <Copy className="size-3.5" aria-hidden />
                    )}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
