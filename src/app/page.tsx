'use client'

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { useQueryClient } from '@tanstack/react-query'
import { ArrowUp, BookOpen, CloudCog, History, KeyRound, Plane, Radar, Star, WifiOff } from 'lucide-react'
import { toast } from 'sonner'
import dynamic from 'next/dynamic'

import { Header } from '@/components/scan/header'
import { StatsStrip } from '@/components/scan/stats-strip'
import { ConfigPanel } from '@/components/scan/config-panel'
import { LiveDashboard } from '@/components/scan/live-dashboard'
import { ResultsPanel } from '@/components/scan/results-panel'
import { HistoryPanel } from '@/components/scan/history-panel'
import { FavoritesPanel } from '@/components/scan/favorites-panel'
import { ShortcutsDialog } from '@/components/scan/shortcuts-dialog'
import { QueuePanel } from '@/components/scan/queue-panel'
import { LockGate } from '@/components/scan/lock'
import { GoogleHunterPanel } from '@/components/scan/google-hunt-panel'
import { WarpPanel } from '@/components/scan/warp-panel'
import { SavedConfigsPanel } from '@/components/scan/saved-configs-panel'
import { IntegrationsPanel } from '@/components/scan/integrations-panel'
import type { ShareMeta } from '@/components/scan/share-dialog'
import { useI18n } from '@/components/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Kbd } from '@/components/ui/kbd'
import { useScanSocket } from '@/hooks/use-scan-socket'
import { sanitizeScanConfig } from '@/lib/format-fa'
import { playChime } from '@/lib/sound'
import { DEFAULT_SCAN_CONFIG, type GoogleHuntSettings, type ScanConfig, type ScanPhase, type ScanSummary } from '@/lib/scan-protocol'
import { cn } from '@/lib/utils'

// shared-report viewer loads only when a ?share= link is opened
const SharedReport = dynamic(
  () => import('@/components/scan/shared-report').then((m) => m.SharedReport),
  { ssr: false },
)

const fadeUp = {
  initial: { opacity: 0, y: 14 },
  animate: { opacity: 1, y: 0 },
}

/** floating "back to top" button — appears after scrolling down */
function ScrollToTop() {
  const { t } = useI18n()
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const onScroll = () => setVisible(window.scrollY > 400)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])
  return (
    <AnimatePresence>
      {visible ? (
        <motion.button
          type="button"
          initial={{ opacity: 0, scale: 0.6, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.6, y: 10 }}
          transition={{ duration: 0.18 }}
          onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
          aria-label={t('page.scrolltop')}
          className="fixed bottom-[calc(1.5rem+env(safe-area-inset-bottom))] start-6 z-40 flex size-11 items-center justify-center rounded-full border border-emerald-500/30 bg-card/90 text-emerald-600 shadow-lg shadow-emerald-500/15 backdrop-blur transition-colors hover:bg-emerald-500/10 dark:text-emerald-400"
        >
          <ArrowUp className="size-5" aria-hidden />
        </motion.button>
      ) : null}
    </AnimatePresence>
  )
}

/** shared subscription for navigator online/offline events */
function subscribeOnline(onChange: () => void) {
  window.addEventListener('online', onChange)
  window.addEventListener('offline', onChange)
  return () => {
    window.removeEventListener('online', onChange)
    window.removeEventListener('offline', onChange)
  }
}

/** fixed offline banner — appears when the browser loses internet connectivity */
function OfflineBanner() {
  const { t } = useI18n()
  // SSR-safe via useSyncExternalStore: server snapshot is always "online",
  // the browser subscribes to the real online/offline events
  const offline = !useSyncExternalStore(
    subscribeOnline,
    () => navigator.onLine,
    () => true,
  )
  return (
    <AnimatePresence>
      {offline ? (
        <motion.div
          initial={{ y: -44, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -44, opacity: 0 }}
          transition={{ duration: 0.2 }}
          role="status"
          className="fixed inset-x-0 top-0 z-50 flex items-center justify-center gap-2 bg-amber-500/95 px-4 py-2 text-xs font-semibold text-amber-950 shadow-lg shadow-amber-500/20 backdrop-blur"
        >
          <WifiOff className="size-3.5 shrink-0" aria-hidden />
          {t('page.offline.banner')}
        </motion.div>
      ) : null}
    </AnimatePresence>
  )
}

/** subtle animated aurora glow behind the whole app (pointer-events: none) */
function AuroraBackground() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <motion.div
        className="absolute -top-32 end-[-10%] size-[520px] rounded-full bg-emerald-500/[0.07] blur-3xl"
        animate={{ x: [0, -40, 0], y: [0, 30, 0] }}
        transition={{ duration: 26, repeat: Infinity, ease: 'easeInOut' }}
      />
      <motion.div
        className="absolute bottom-[-20%] start-[-8%] size-[460px] rounded-full bg-teal-500/[0.06] blur-3xl"
        animate={{ x: [0, 36, 0], y: [0, -26, 0] }}
        transition={{ duration: 32, repeat: Infinity, ease: 'easeInOut' }}
      />
      <div
        className="absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage: 'radial-gradient(hsl(var(--border)) 1px, transparent 1px)',
          backgroundSize: '26px 26px',
          maskImage: 'radial-gradient(ellipse 90% 60% at 50% 0%, black 30%, transparent 75%)',
          WebkitMaskImage: 'radial-gradient(ellipse 90% 60% at 50% 0%, black 30%, transparent 75%)',
        }}
      />
    </div>
  )
}

export default function Home() {
  const { t, num, dir, lang } = useI18n()
  const qc = useQueryClient()
  const {
    connected,
    running,
    progress,
    results,
    logs,
    summary,
    rtt,
    latencyHistory,
    finishedCount,
    autoState,
    queueState,
    start,
    stop,
    checkIps,
    setAutoScan,
    testNotify,
    setTelegram,
    testTelegram,
    addToQueue,
    removeFromQueue,
    clearQueue,
    moveQueueItem,
    reorderQueueItem,
    toggleQueueItem,
    updateQueueItem,
    probeXray,
    huntState,
    huntSchedState,
    setHuntSchedule,
    startHunt,
    stopHunt,
    resetHunt,
    reconState,
    refreshRecon,
    warpState,
    startWarp,
    stopWarp,
    resetWarp,
  } = useScanSocket()

  const [config, setConfig] = useState<ScanConfig>(() => ({
    ...DEFAULT_SCAN_CONFIG,
  }))
  const [savedId, setSavedId] = useState<string | null>(null)
  const [tabValue, setTabValue] = useState('live')
  const [shortcutsOpen, setShortcutsOpen] = useState(false)
  // `?share=<scanId>` — opened via a share link → read-only report dialog
  const [sharedScanId, setSharedScanId] = useState<string | null>(null)
  const startConfigRef = useRef<ScanConfig | null>(null)
  const summaryRef = useRef<ScanSummary | null>(null)
  const lastHandledFinishRef = useRef(0)
  const savedKeysRef = useRef<Set<string>>(new Set())

  useEffect(() => {
    summaryRef.current = summary
  }, [summary])

  const phase: ScanPhase = useMemo(() => {
    if (running) return progress?.phase ?? 'generating'
    if (summary) {
      if (summary.status === 'done') return 'done'
      if (summary.status === 'stopped') return 'stopped'
      return 'error'
    }
    return 'idle'
  }, [running, progress, summary])

  // ----- auto-save finished scans (done / stopped, with results) -----
  const saveScan = useCallback(
    async (s: ScanSummary) => {
      const cfg = startConfigRef.current
      const body = {
        summary: s,
        rangesText: cfg?.customRanges ?? s.config?.customRanges ?? '',
        label:
          cfg?.preset === 'custom' ? 'رنج سفارشی' : undefined,
      }
      try {
        const res = await fetch('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        })
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = (await res.json()) as { scan?: { id?: string } }
        setSavedId(data?.scan?.id ?? null)
        toast.success(t('page.toast.saved', { n: num(s.results.length) }))
        qc.invalidateQueries({ queryKey: ['stats'] })
        qc.invalidateQueries({ queryKey: ['scans'] })
      } catch {
        toast.error(t('page.toast.savefail'))
      }
    },
    [qc, t, num]
  )

  useEffect(() => {
    if (finishedCount <= lastHandledFinishRef.current) return
    lastHandledFinishRef.current = finishedCount
    const s = summaryRef.current
    if (!s || s.results.length === 0) return
    if (s.status === 'done') {
      if (s.viaQueue) {
        toast.success(t('page.toast.queue.done', { n: num(s.results.length) }))
        playChime('queue')
      } else {
        toast.success(t('page.toast.done', { n: num(s.results.length) }))
        playChime('success')
      }
    } else if (s.status === 'stopped') {
      toast.info(t('page.toast.stopped', { n: num(s.results.length) }))
      playChime('info')
    } else {
      playChime('error')
      return
    }
    // scheduled runs are persisted by the ENGINE itself (works without a browser)
    if (s.savedScanId) {
      setSavedId(s.savedScanId)
      qc.invalidateQueries({ queryKey: ['stats'] })
      qc.invalidateQueries({ queryKey: ['scans'] })
      return
    }
    const key = String(s.startedAt)
    if (savedKeysRef.current.has(key)) return
    savedKeysRef.current.add(key)
    void saveScan(s)
  }, [finishedCount, saveScan, qc])

  // ----- scheduled auto-scan toggle (engine-side) -----
  const handleAutoSet = useCallback(
    async (enabled: boolean, intervalMinutes: number, notifyUrl?: string) => {
      if (!connected) {
        toast.error(t('page.toast.offline'))
        return
      }
      if (enabled) {
        const cfgState = configRef.current
        if (cfgState.preset === 'custom' && !(cfgState.customRanges ?? '').trim()) {
          toast.error(t('page.toast.cidr.auto'))
          return
        }
        const state = await setAutoScan(true, intervalMinutes, sanitizeScanConfig(cfgState), notifyUrl)
        if (state?.enabled) {
          toast.success(t('page.toast.auto.on', { n: num(intervalMinutes) }))
        } else {
          toast.error(t('page.toast.auto.onfail'))
        }
      } else {
        const state = await setAutoScan(false, intervalMinutes, null, notifyUrl)
        if (state && !state.enabled) {
          toast.info(t('page.toast.auto.off'))
        } else {
          toast.error(t('page.toast.auto.offfail'))
        }
      }
    },
    [connected, setAutoScan, t, num],
  )

  // ----- webhook test (engine-side fetch) -----
  const handleNotifyTest = useCallback(
    async (url: string) => {
      const ok = await testNotify(url)
      if (ok) toast.success(t('page.toast.notify.ok'))
      else toast.error(t('page.toast.notify.fail'))
      return ok
    },
    [testNotify, t],
  )

  // ----- telegram credentials + test (digest toggles message batching for queue runs) -----
  const handleTelegramSet = useCallback(
    async (token?: string, chatId?: string, digest?: boolean) => {
      const state = await setTelegram(token, chatId, digest)
      if (state) {
        if (digest !== undefined) {
          toast.success(t(digest ? 'config.tg.digest.on' : 'config.tg.digest.off'))
        } else {
          toast.success(t('page.toast.tg.saved'))
        }
        return true
      }
      toast.error(t('page.toast.offline'))
      return false
    },
    [setTelegram, t],
  )

  const handleTelegramTest = useCallback(async () => {
    const ok = await testTelegram()
    if (ok) toast.success(t('page.toast.tg.ok'))
    else toast.error(t('page.toast.tg.fail'))
    return ok
  }, [testTelegram, t])

  // ----- multi-CDN queue actions -----
  const handleQueueAdd = useCallback(async () => {
    if (!connected) {
      toast.error(t('page.toast.offline'))
      return
    }
    const cfgState = configRef.current
    if (cfgState.preset === 'custom' && !(cfgState.customRanges ?? '').trim()) {
      toast.error(t('page.toast.cidr.start'))
      return
    }
    const cfg = sanitizeScanConfig(cfgState)
    const label =
      cfg.preset === 'custom'
        ? t('config.preset.custom')
        : t(`preset.${cfg.preset}` as Parameters<typeof t>[0])
    const state = await addToQueue(cfg, label)
    if (state) {
      const waiting = state.items.filter((i) => i.status === 'waiting').length
      toast.success(t('queue.toast.add', { label, n: num(waiting) }))
    } else {
      toast.error(t('queue.toast.add.fail'))
    }
  }, [connected, addToQueue, t, num])

  const handleQueueRemove = useCallback(
    async (id: string) => {
      const state = await removeFromQueue(id)
      if (state) toast.success(t('queue.toast.remove'))
      else toast.error(t('queue.toast.remove.fail'))
    },
    [removeFromQueue, t],
  )

  const handleQueueClear = useCallback(async () => {
    const state = await clearQueue()
    if (state) toast.success(t('queue.toast.cleared'))
    else toast.error(t('queue.toast.remove.fail'))
  }, [clearQueue, t])

  const handleQueueMove = useCallback(
    async (id: string, dir: -1 | 1) => {
      const state = await moveQueueItem(id, dir)
      if (!state) toast.error(t('queue.toast.remove.fail'))
    },
    [moveQueueItem, t],
  )

  const handleQueueReorder = useCallback(
    async (id: string, index: number) => {
      const state = await reorderQueueItem(id, index)
      if (state) toast.success(t('queue.toast.reordered'))
      else toast.error(t('queue.toast.remove.fail'))
    },
    [reorderQueueItem, t],
  )

  const handleQueueToggle = useCallback(
    async (id: string) => {
      const state = await toggleQueueItem(id)
      if (!state) toast.error(t('queue.toast.remove.fail'))
    },
    [toggleQueueItem, t],
  )

  const handleQueueEdit = useCallback(
    async (id: string, patch: { label?: string; config?: Partial<ScanConfig> }) => {
      const state = await updateQueueItem(id, patch)
      if (state) {
        toast.success(t('queue.toast.updated'))
        return true
      }
      toast.error(t('queue.toast.remove.fail'))
      return false
    },
    [updateQueueItem, t],
  )

  // share report context (preset at start time + scan start timestamp)
  const [startedTs, setStartedTs] = useState<number | null>(null)
  const shareMeta: ShareMeta | null = useMemo(() => {
    // queue/auto runs carry their config inside the summary — manual runs use the start ref
    const cfg = summary?.config ?? startConfigRef.current
    const ts = summary?.startedAt ?? startedTs
    if (!cfg?.preset && !ts) return null
    return {
      preset:
        cfg?.preset && cfg.preset !== 'custom'
          ? t(`preset.${cfg.preset}` as Parameters<typeof t>[0])
          : cfg?.preset === 'custom'
            ? t('config.preset.custom')
            : undefined,
      date: ts ?? undefined,
      port: cfg?.port,
      total: summary?.totalIPs ?? progress?.total,
      alive: summary?.alive ?? progress?.alive,
    }
  }, [summary, startedTs, progress, t])

  const handleStart = useCallback(
    (cfg: ScanConfig) => {
      startConfigRef.current = cfg
      setSavedId(null)
      setStartedTs(Date.now())
      start(cfg)
    },
    [start]
  )

  const handleStop = useCallback(() => stop(), [stop])

  // ----- standalone Google IP hunter (fully independent of the scan pipeline) -----
  const handleHuntStart = useCallback(
    async (settings?: Partial<GoogleHuntSettings>) => {
      if (!connected) {
        toast.error(t('hunt.offline'))
        return null
      }
      return startHunt(settings)
    },
    [connected, startHunt, t],
  )

  // ----- keyboard shortcuts (shared sanitize logic via sanitizeScanConfig) -----
  const configRef = useRef(config)
  useEffect(() => {
    configRef.current = config
  }, [config])

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null
      const typing =
        !!target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.isContentEditable)
      const mod = e.ctrlKey || e.metaKey

      if (mod && e.key === 'Enter') {
        e.preventDefault()
        const { connected: c, running: r } = stateRef.current
        const cfgState = configRef.current
        if (!c || r) return
        if (cfgState.preset === 'custom' && !(cfgState.customRanges ?? '').trim()) {
          toast.error(t('page.toast.cidr.start'))
          setTabValue('live')
          return
        }
        handleStart(sanitizeScanConfig(cfgState))
        return
      }
      if (mod && e.key === '.') {
        e.preventDefault()
        if (stateRef.current.running) handleStop()
        return
      }
      if (e.altKey && (e.key === '1' || e.key === '2' || e.key === '3')) {
        e.preventDefault()
        setTabValue(e.key === '1' ? 'live' : e.key === '2' ? 'history' : 'favorites')
        return
      }
      if (e.altKey && (e.key === 'b' || e.key === 'B')) {
        e.preventDefault()
        setTabValue('live')
        window.dispatchEvent(new CustomEvent('results:batch-probe'))
        return
      }
      if (!typing && (e.key === '?' || (e.shiftKey && e.key === '/'))) {
        e.preventDefault()
        setShortcutsOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [handleStart, handleStop, t])

  const stateRef = useRef({ connected, running })
  useEffect(() => {
    stateRef.current = { connected, running }
  }, [connected, running])

  // keep document.title in sync with the active language (SSR title is Persian-only)
  useEffect(() => {
    document.title =
      lang === 'fa'
        ? 'Clean IP Scanner — نسخه وب'
        : 'Clean IP Scanner — Web Edition'
  }, [lang])

  // hunt v6.3 — healthy IPv4 addresses of the live hunt (v6 filtered out; DDNS pushes are A-records only)
  const huntHealthyIps = useMemo(
    () =>
      (huntState?.healthyIps ?? [])
        .filter((c) => !c.v6 && !c.ip.includes(':'))
        .map((c) => c.ip),
    [huntState],
  )

  // hunt v6.4 — healthy IPv6 addresses of the live hunt (feeds the DDNS AAAA push)
  const huntHealthyIpsV6 = useMemo(
    () => (huntState?.healthyIps ?? []).filter((c) => c.v6 === true).map((c) => c.ip),
    [huntState],
  )

  // open a shared report when the page is loaded with ?share=<scanId>
  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search)
      const id = params.get('share')
      if (id && /^[a-z0-9]{6,40}$/i.test(id)) {
        setSharedScanId(id)
      }
      // strip the param so refreshes/reloads don't re-trigger the dialog
      if (id !== null) {
        params.delete('share')
        const qs = params.toString()
        window.history.replaceState(
          null,
          '',
          window.location.pathname + (qs ? `?${qs}` : ''),
        )
      }
    } catch {
      /* ignore malformed URLs */
    }
  }, [])

  return (
    <div className="flex min-h-screen flex-col bg-background" dir={dir}>
      <AuroraBackground />
      <LockGate />
      <OfflineBanner />
      <Header connected={connected} rtt={rtt} />

      <main className="mx-auto w-full max-w-7xl flex-1 space-y-6 px-4 py-6">
        {/* Stats */}
        <motion.section {...fadeUp} transition={{ duration: 0.4 }}>
          <StatsStrip />
        </motion.section>

        <Tabs defaultValue="live" dir={dir} value={tabValue} onValueChange={setTabValue} className="gap-6 space-y-0">
          <TabsList className="scrollbar-thin h-11 w-full justify-stretch gap-1 overflow-x-auto p-1 sm:w-auto sm:justify-start sm:overflow-visible">
            <TabsTrigger
              value="live"
              className="min-h-9 shrink-0 gap-1 whitespace-nowrap px-2.5 text-xs sm:flex-1 sm:flex-none sm:gap-1.5 sm:px-4 sm:text-sm"
            >
              <Radar className="size-4" aria-hidden />
              {t('tab.live')}
            </TabsTrigger>
            <TabsTrigger
              value="warp"
              className="min-h-9 shrink-0 gap-1 whitespace-nowrap px-2.5 text-xs sm:flex-1 sm:flex-none sm:gap-1.5 sm:px-4 sm:text-sm"
            >
              <Plane className="size-4" aria-hidden />
              {t('tab.warp')}
            </TabsTrigger>
            <TabsTrigger
              value="configs"
              className="min-h-9 shrink-0 gap-1 whitespace-nowrap px-2.5 text-xs sm:flex-1 sm:flex-none sm:gap-1.5 sm:px-4 sm:text-sm"
            >
              <KeyRound className="size-4" aria-hidden />
              {t('tab.configs')}
            </TabsTrigger>
            <TabsTrigger
              value="integrations"
              className="min-h-9 shrink-0 gap-1 whitespace-nowrap px-2.5 text-xs sm:flex-1 sm:flex-none sm:gap-1.5 sm:px-4 sm:text-sm"
            >
              <CloudCog className="size-4" aria-hidden />
              {t('tab.integrations')}
            </TabsTrigger>
            <TabsTrigger
              value="history"
              className="min-h-9 shrink-0 gap-1 whitespace-nowrap px-2.5 text-xs sm:flex-1 sm:flex-none sm:gap-1.5 sm:px-4 sm:text-sm"
            >
              <History className="size-4" aria-hidden />
              {t('tab.history')}
            </TabsTrigger>
            <TabsTrigger
              value="favorites"
              className="min-h-9 shrink-0 gap-1 whitespace-nowrap px-2.5 text-xs sm:flex-1 sm:flex-none sm:gap-1.5 sm:px-4 sm:text-sm"
            >
              <Star className="size-4" aria-hidden />
              {t('tab.favorites')}
            </TabsTrigger>
          </TabsList>

          {/* Live scan tab */}
          <TabsContent value="live">
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
              <motion.div
                className="space-y-6 lg:col-span-2"
                {...fadeUp}
                transition={{ duration: 0.4, delay: 0.05 }}
              >
                <ConfigPanel
                  config={config}
                  onConfigChange={setConfig}
                  running={running}
                  connected={connected}
                  onStart={handleStart}
                  onStop={handleStop}
                  autoState={autoState}
                  onAutoSet={handleAutoSet}
                  onNotifyTest={handleNotifyTest}
                  onTelegramSet={handleTelegramSet}
                  onTelegramTest={handleTelegramTest}
                />
                <QueuePanel
                  connected={connected}
                  queueState={queueState}
                  onAdd={handleQueueAdd}
                  onRemove={handleQueueRemove}
                  onClear={handleQueueClear}
                  onMove={handleQueueMove}
                  onReorder={handleQueueReorder}
                  onToggle={handleQueueToggle}
                  onEdit={handleQueueEdit}
                />
              </motion.div>

              <div className="space-y-6 lg:col-span-3">
                <motion.div {...fadeUp} transition={{ duration: 0.4, delay: 0.1 }}>
                  <LiveDashboard
                    running={running}
                    phase={phase}
                    progress={progress}
                    summary={summary}
                    logs={logs}
                    latencyHistory={latencyHistory}
                  />
                </motion.div>
                <motion.div {...fadeUp} transition={{ duration: 0.4, delay: 0.15 }}>
                  <ResultsPanel
                    results={results}
                    running={running}
                    savedId={savedId}
                    shareMeta={shareMeta}
                    preset={summary?.config?.preset ?? config.preset}
                    port={summary?.config?.port ?? config.port}
                    connected={connected}
                    onProbe={probeXray}
                  />
                </motion.div>
              </div>
            </div>

            {/* Standalone Google IP hunter — independent of the scan pipeline above */}
            <motion.section {...fadeUp} transition={{ duration: 0.4, delay: 0.2 }} className="mt-6">
              <GoogleHunterPanel
                connected={connected}
                huntState={huntState}
                recon={reconState}
                schedState={huntSchedState}
                onStart={handleHuntStart}
                onStop={stopHunt}
                onReset={resetHunt}
                onRefreshRecon={refreshRecon}
                onSetSchedule={setHuntSchedule}
              />
            </motion.section>
          </TabsContent>

          {/* WARP endpoint scanner tab (v6.2) — standalone WireGuard UDP probing */}
          <TabsContent value="warp">
            <motion.section {...fadeUp} transition={{ duration: 0.4, delay: 0.05 }}>
              <WarpPanel
                connected={connected}
                warpState={warpState}
                onStart={startWarp}
                onStop={stopWarp}
                onReset={resetWarp}
              />
            </motion.section>
          </TabsContent>

          {/* Saved configs + subscription tab (v6.2) */}
          <TabsContent value="configs">
            <motion.section {...fadeUp} transition={{ duration: 0.4, delay: 0.05 }}>
              <SavedConfigsPanel />
            </motion.section>
          </TabsContent>

          {/* Integrations tab (v6.3) — Cloudflare DDNS push + Telegram hunt/WARP digests (v6.6) */}
          <TabsContent value="integrations">
            <motion.section {...fadeUp} transition={{ duration: 0.4, delay: 0.05 }}>
              <IntegrationsPanel
                connected={connected}
                healthyIps={huntHealthyIps}
                healthyIpsV6={huntHealthyIpsV6}
                huntState={huntState}
                warpState={warpState}
                schedJournal={huntSchedState.journal ?? []}
              />
            </motion.section>
          </TabsContent>

          {/* History tab */}
          <TabsContent value="history">
            <HistoryPanel />
          </TabsContent>

          {/* Favorites tab */}
          <TabsContent value="favorites">
            <FavoritesPanel checkIps={checkIps} connected={connected} port={config.port || 443} />
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer — sticks to bottom (mt-auto) and is pushed naturally on overflow */}
      <footer className="mt-auto border-t bg-background/60">
        <div className="mx-auto flex w-full max-w-7xl flex-col items-center justify-between gap-2 px-4 pb-[max(1rem,env(safe-area-inset-bottom))] pt-4 text-xs text-muted-foreground sm:flex-row">
          <a
            href="https://github.com/CheginiSoroush/clean-ip-scanner"
            target="_blank"
            rel="noreferrer"
            className="text-center transition-colors hover:text-foreground sm:text-start"
            aria-label={t('header.github')}
          >
            {t('page.made')}
          </a>
          <div className="flex items-center gap-3">
            <a
              href="https://cheginisoroush.github.io/clean-ip-scanner/"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 font-medium transition-colors hover:text-emerald-500"
              aria-label={t('page.handbook.aria')}
            >
              <BookOpen className="size-3.5" />
              <span>{t('page.handbook')}</span>
            </a>
            <button
              type="button"
              onClick={() => setShortcutsOpen(true)}
              className="hidden items-center gap-1.5 transition-colors hover:text-foreground sm:inline-flex"
              aria-label={t('page.shortcuts.aria')}
            >
              <span>{t('page.shortcuts')}</span>
              <span className="flex items-center gap-1" dir="ltr">
                <Kbd>?</Kbd>
              </span>
            </button>
            <Badge variant="outline" className="font-mono">
              v7.6.0-web
            </Badge>
          </div>
        </div>
      </footer>

      <ShortcutsDialog open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
      <SharedReport scanId={sharedScanId} onClear={() => setSharedScanId(null)} />
      <ScrollToTop />
    </div>
  )
}
