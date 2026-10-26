'use client'

import { memo, useEffect, useRef, useState } from 'react'
import {
  Bell,
  Bot,
  Check,
  ChevronDown,
  Clock,
  Info,
  Layers,
  PenLine,
  Play,
  Send,
  Settings2,
  Square,
  Timer,
  X,
} from 'lucide-react'
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
import { Button } from '@/components/ui/button'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Slider } from '@/components/ui/slider'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { CDN_PRESETS } from '@/lib/cdn-presets'
import { formatDurationHMS, sanitizeScanConfig } from '@/lib/format-fa'
import { DEFAULT_SCAN_CONFIG, type AutoScanState, type ScanConfig } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'
import { cn } from '@/lib/utils'

interface ConfigPanelProps {
  config: ScanConfig
  onConfigChange: (next: ScanConfig) => void
  running: boolean
  connected: boolean
  onStart: (cfg: ScanConfig) => void
  onStop: () => void
  /** live engine-side scheduler state (null until synced) */
  autoState: AutoScanState | null
  /** toggle the engine-side scheduler — page.tsx attaches the sanitized config */
  onAutoSet: (enabled: boolean, intervalMinutes: number, notifyUrl?: string) => void
  /** send a test webhook; resolves true on success (page.tsx owns the toasts) */
  onNotifyTest: (url: string) => Promise<boolean>
  /** store Telegram credentials on the engine; resolves true on success (digest = queue batch digest) */
  onTelegramSet: (token?: string, chatId?: string, digest?: boolean) => Promise<boolean>
  /** send a Telegram test message; resolves true on success */
  onTelegramTest: () => Promise<boolean>
}

/** ticking countdown to the next scheduled run (engine clock) */
function useCountdownMs(target: number | null): number | null {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (target == null) return
    const id = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [target])
  return target == null ? null : Math.max(0, target - now)
}

/** accent token → tailwind bg class (no blue/indigo allowed) */
const ACCENT_DOT: Record<string, string> = {
  orange: 'bg-orange-500',
  emerald: 'bg-emerald-500',
  rose: 'bg-rose-500',
  violet: 'bg-violet-500',
  cyan: 'bg-cyan-500',
  teal: 'bg-teal-500',
  amber: 'bg-amber-500',
  zinc: 'bg-zinc-400',
}

interface PresetOption {
  id: string
  scale: string
  accent: string
}

const PRESET_OPTIONS: PresetOption[] = [
  ...CDN_PRESETS.map((p) => ({
    id: p.id,
    scale: p.scale,
    accent: p.accent,
  })),
  {
    id: 'custom',
    scale: '—',
    accent: 'zinc',
  },
]

function ParamSlider({
  label,
  hint,
  value,
  min,
  max,
  step,
  display,
  disabled,
  onChange,
}: {
  label: string
  hint?: string
  value: number
  min: number
  max: number
  step: number
  display: (v: number) => string
  disabled?: boolean
  onChange: (v: number) => void
}) {
  return (
    <div className="space-y-2.5">
      <div className="flex items-center justify-between gap-2">
        <Label className="text-[13px] font-medium">{label}</Label>
        <span
          dir="ltr"
          className="rounded-md bg-muted px-2 py-0.5 font-mono text-xs tabular-nums"
        >
          {display(value)}
        </span>
      </div>
      <Slider
        value={[value]}
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        onValueChange={(v) => onChange(Array.isArray(v) ? (v[0] ?? min) : min)}
        aria-label={label}
        className="w-full"
      />
      {hint ? (
        <p className="text-[11px] leading-4 text-muted-foreground">{hint}</p>
      ) : null}
    </div>
  )
}

function ConfigPanelInner({
  config,
  onConfigChange,
  running,
  connected,
  onStart,
  onStop,
  autoState,
  onAutoSet,
  onNotifyTest,
  onTelegramSet,
  onTelegramTest,
}: ConfigPanelProps) {
  const { t, num, dir, dateLocale } = useI18n()
  const [advOpen, setAdvOpen] = useState(false)
  const [autoOpen, setAutoOpen] = useState(false)
  // local slider override — engine value wins until the user moves the slider
  const [intervalOverride, setIntervalOverride] = useState<number | null>(null)
  // local webhook url input (seeded from the engine state)
  const [notifyUrl, setNotifyUrl] = useState('')
  const [notifyTesting, setNotifyTesting] = useState(false)
  // local telegram inputs — the token is write-only (engine never echoes it back)
  const [tgToken, setTgToken] = useState('')
  const [tgChatId, setTgChatId] = useState('')
  const [tgTesting, setTgTesting] = useState(false)
  const [tgDigestPending, setTgDigestPending] = useState(false)
  // last values actually committed to the engine ('' = cleared) — prevents duplicate saves
  const tgCommittedRef = useRef<{ token: string; chatId: string }>({ token: '', chatId: '' })
  const intervalMin = intervalOverride ?? autoState?.intervalMinutes ?? 30

  // keep the local notify input in sync with the engine state
  useEffect(() => {
    if (autoState && autoState.notifyUrl !== notifyUrl) {
      setNotifyUrl(autoState.notifyUrl ?? '')
    }
  }, [autoState])

  const autoEnabled = !!autoState?.enabled
  const countdownMs = useCountdownMs(autoEnabled ? autoState?.nextRunAt ?? null : null)

  const patch = (p: Partial<ScanConfig>) => onConfigChange({ ...config, ...p })

  const isCustom = config.preset === 'custom'
  const rangesEmpty = !(config.customRanges ?? '').trim()
  const startDisabled =
    running || !connected || (isCustom && rangesEmpty)

  const handleStart = () => {
    onStart(sanitizeScanConfig(config))
  }

  const commitNotify = (url: string) => {
    onAutoSet(autoEnabled, intervalMin, url.trim())
  }

  const handleNotifyTest = async () => {
    const url = notifyUrl.trim()
    if (!url || notifyTesting) return
    setNotifyTesting(true)
    try {
      await onNotifyTest(url)
    } finally {
      setNotifyTesting(false)
    }
  }

  const tgConfigured = !!autoState?.telegramConfigured
  const tgDigest = !!autoState?.telegramDigest

  /** flip the digest mode — finished queue runs are merged into ONE telegram message */
  const toggleDigest = async (v: boolean) => {
    setTgDigestPending(true)
    try {
      await onTelegramSet(undefined, undefined, v)
    } finally {
      setTgDigestPending(false)
    }
  }

  /** save-on-blur: only when a NEW token was typed or the chat id differs from the engine state */
  const commitTelegram = async (token: string, chatId: string) => {
    const nextToken = token.trim()
    const nextChat = chatId.trim()
    const tokenTouched = nextToken !== '' && nextToken !== tgCommittedRef.current.token
    const chatChanged = nextChat !== (autoState?.telegramChatId ?? '')
    if (!tokenTouched && !chatChanged) return
    tgCommittedRef.current = { token: nextToken || tgCommittedRef.current.token, chatId: nextChat }
    await onTelegramSet(tokenTouched ? nextToken : undefined, chatChanged ? nextChat : undefined)
  }

  /** explicit reset — clears both credentials on the engine */
  const clearTelegram = async () => {
    setTgToken('')
    setTgChatId('')
    tgCommittedRef.current = { token: '', chatId: '' }
    await onTelegramSet('', '')
  }

  const handleTelegramTest = async () => {
    if (tgTesting) return
    setTgTesting(true)
    try {
      await onTelegramTest()
    } finally {
      setTgTesting(false)
    }
  }

  const presetNameKey = (id: string): DictKey =>
    id === 'custom' ? 'config.preset.custom' : (`preset.${id}` as DictKey)
  const presetDescKey = (id: string): DictKey =>
    id === 'custom' ? 'config.preset.desc.custom' : (`presetDesc.${id}` as DictKey)

  const selectedPreset = PRESET_OPTIONS.find((p) => p.id === config.preset)

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6">
      {/* Title */}
      <div className="flex items-center gap-2">
        <span className="flex size-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
          <Settings2 className="size-4" aria-hidden />
        </span>
        <h2 className="text-base font-bold">{t('config.title')}</h2>
        {running ? (
          <span className="ms-auto inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-2.5 py-0.5 text-[11px] font-medium text-amber-600 dark:text-amber-400">
            <span className="size-1.5 animate-pulse rounded-full bg-amber-500" />
            {t('config.running')}
          </span>
        ) : null}
      </div>

      {/* Preset picker */}
      <div className="mt-5 space-y-2.5">
        <div className="flex items-center gap-1.5 text-[13px] font-medium">
          <Layers className="size-3.5 text-muted-foreground" aria-hidden />
          {t('config.preset.label')}
        </div>
        <div
          role="radiogroup"
          aria-label={t('config.preset.aria')}
          className="grid grid-cols-2 gap-2 sm:grid-cols-3"
        >
          {PRESET_OPTIONS.map((p) => {
            const selected = config.preset === p.id
            return (
              <button
                key={p.id}
                type="button"
                role="radio"
                aria-checked={selected}
                title={t(presetDescKey(p.id))}
                onClick={() => patch({ preset: p.id })}
                className={cn(
                  'group relative flex min-h-11 flex-col items-start gap-1 rounded-lg border p-2.5 text-start transition-all hover:border-emerald-500/40 hover:bg-emerald-500/5 hover:shadow-[0_0_18px_-6px_rgba(16,185,129,0.45)]',
                  selected
                    ? 'border-emerald-500 bg-emerald-500/5 ring-1 ring-emerald-500 shadow-lg shadow-emerald-500/10 scale-[1.02]'
                    : 'border-border bg-background/40'
                )}
              >
                {/* gradient top hairline — brightens on hover, steady when selected */}
                <span
                  aria-hidden
                  className={cn(
                    'absolute inset-x-2 top-0 h-px bg-gradient-to-l from-transparent via-emerald-400/70 to-transparent transition-opacity',
                    selected ? 'opacity-100' : 'opacity-0 group-hover:opacity-70'
                  )}
                />
                <span className="flex w-full items-center gap-1.5">
                  {p.id === 'custom' ? (
                    <PenLine className="size-3.5 text-muted-foreground" aria-hidden />
                  ) : (
                    <span
                      className={cn(
                        'size-2 shrink-0 rounded-full',
                        ACCENT_DOT[p.accent] ?? 'bg-zinc-400'
                      )}
                      aria-hidden
                    />
                  )}
                  <span className="truncate text-xs font-semibold">
                    {t(presetNameKey(p.id))}
                  </span>
                </span>
                <span
                  dir="ltr"
                  className="font-mono text-[10px] text-muted-foreground"
                >
                  {p.scale}
                </span>
                {selected ? (
                  <Check
                    className="absolute -top-1.5 end-1.5 size-4 rounded-full bg-emerald-500 p-0.5 text-white"
                    aria-hidden
                  />
                ) : null}
              </button>
            )
          })}
        </div>
        {selectedPreset ? (
          <p className="text-[11px] leading-4 text-muted-foreground">
            {t(presetDescKey(selectedPreset.id))}
          </p>
        ) : null}
      </div>

      {/* Custom ranges */}
      <div className="mt-5 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <Label htmlFor="custom-ranges" className="text-[13px] font-medium">
            {t('config.ranges.label')}
          </Label>
          <span className="text-[10px] text-muted-foreground">
            {isCustom ? t('config.ranges.hint.only') : t('config.ranges.hint.merge')}
          </span>
        </div>
        <Textarea
          id="custom-ranges"
          dir="ltr"
          rows={4}
          spellCheck={false}
          className="scrollbar-thin min-h-20 resize-y bg-background/40 font-mono text-xs"
          placeholder={'103.21.244.0/22\n104.16.0.0/13\n172.64.0.0/13'}
          value={config.customRanges ?? ''}
          onChange={(e) => patch({ customRanges: e.target.value })}
        />
        <p className="text-[11px] leading-4 text-muted-foreground">
          {t('config.ranges.help.prefix')} <span dir="ltr" className="font-mono">103.21.244.0/22</span>
          {' · '}
          {isCustom ? t('config.ranges.help.only') : t('config.ranges.help.merge')}
        </p>
      </div>

      {/* Params */}
      <div className="mt-6 grid grid-cols-1 gap-5 sm:grid-cols-2">
        <div className="space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <Label htmlFor="scan-port" className="text-[13px] font-medium">
              {t('config.port.label')}
            </Label>
          </div>
          <Input
            id="scan-port"
            dir="ltr"
            type="number"
            inputMode="numeric"
            min={1}
            max={65535}
            className="h-9 bg-background/40 font-mono text-sm"
            value={config.port || ''}
            onChange={(e) => {
              const v = parseInt(e.target.value, 10)
              patch({ port: Number.isFinite(v) ? v : 0 })
            }}
            aria-label={t('config.port.aria')}
          />
          <p className="text-[11px] text-muted-foreground">
            {t('config.port.hint')}
          </p>
        </div>

        <ParamSlider
          label={t('config.ping.label')}
          value={config.pingCount}
          min={1}
          max={8}
          step={1}
          display={(v) => `${num(v)}×`}
          disabled={running}
          onChange={(v) => patch({ pingCount: v })}
          hint={t('config.ping.hint')}
        />

        <ParamSlider
          label={t('config.timeout.label')}
          value={config.timeoutMs}
          min={200}
          max={5000}
          step={100}
          display={(v) => `${num(v)} ms`}
          disabled={running}
          onChange={(v) => patch({ timeoutMs: v })}
          hint={t('config.timeout.hint')}
        />

        <ParamSlider
          label={t('config.conc.label')}
          value={config.concurrency}
          min={16}
          max={1024}
          step={16}
          display={(v) => num(v)}
          disabled={running}
          onChange={(v) => patch({ concurrency: v })}
          hint={t('config.conc.hint')}
        />

        <ParamSlider
          label={t('config.maxips.label')}
          value={config.maxIPs}
          min={50}
          max={50000}
          step={50}
          display={(v) => num(v)}
          disabled={running}
          onChange={(v) => patch({ maxIPs: v })}
          hint={t('config.maxips.hint')}
        />

        <ParamSlider
          label={t('config.speedtest.label')}
          value={config.speedTestCount}
          min={1}
          max={30}
          step={1}
          display={(v) => num(v)}
          disabled={running}
          onChange={(v) => patch({ speedTestCount: v })}
          hint={t('config.speedtest.hint')}
        />
      </div>

      {/* Estimated line */}
      <div className="mt-5 flex items-start gap-1.5 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-2.5 text-[12px] text-emerald-700 dark:text-emerald-300">
        <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        <span>{t('config.estimate', { n: num(config.maxIPs) })}</span>
      </div>

      {/* Advanced */}
      <Collapsible open={advOpen} onOpenChange={setAdvOpen}>
        <CollapsibleTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className="mt-3 h-9 w-full justify-between px-3 text-muted-foreground hover:text-foreground"
            aria-expanded={advOpen}
          >
            <span className="text-[13px] font-medium">{t('config.adv.title')}</span>
            <ChevronDown
              className={cn(
                'size-4 transition-transform',
                advOpen && 'rotate-180'
              )}
              aria-hidden
            />
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-4 overflow-hidden pt-2">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="speed-host" className="text-[13px] font-medium">
                {t('config.speedhost.label')}
              </Label>
              <Input
                id="speed-host"
                dir="ltr"
                spellCheck={false}
                className="h-9 bg-background/40 font-mono text-sm"
                placeholder="speed.cloudflare.com"
                value={config.speedHost ?? ''}
                onChange={(e) => patch({ speedHost: e.target.value })}
              />
              <p className="text-[11px] text-muted-foreground">
                {t('config.speedhost.hint')}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="max-latency" className="text-[13px] font-medium">
                {t('config.maxlat.label')}
              </Label>
              <Input
                id="max-latency"
                dir="ltr"
                type="number"
                inputMode="numeric"
                min={0}
                step={50}
                className="h-9 bg-background/40 font-mono text-sm"
                value={config.maxLatencyMs ?? 0}
                onChange={(e) => {
                  const v = parseInt(e.target.value, 10)
                  patch({ maxLatencyMs: Number.isFinite(v) ? Math.max(0, v) : 0 })
                }}
                aria-label={t('config.maxlat.aria')}
              />
              <p className="text-[11px] text-muted-foreground">
                {t('config.maxlat.hint')}
              </p>
            </div>
          </div>
        </CollapsibleContent>
      </Collapsible>

      {/* Scheduled auto-scan */}
      <Collapsible open={autoOpen} onOpenChange={setAutoOpen}>
        <CollapsibleTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className={cn(
              'mt-2 h-9 w-full justify-between px-3 text-muted-foreground hover:text-foreground',
              autoEnabled && 'text-emerald-600 dark:text-emerald-400'
            )}
            aria-expanded={autoOpen}
          >
            <span className="flex items-center gap-2 text-[13px] font-medium">
              <Timer className="size-3.5" aria-hidden />
              {t('config.auto.title')}
              {autoEnabled ? (
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-600 dark:text-emerald-400">
                  <span className="size-1.5 animate-pulse rounded-full bg-emerald-500" aria-hidden />
                  {t('config.auto.badge')}
                </span>
              ) : null}
            </span>
            <ChevronDown
              className={cn('size-4 transition-transform', autoOpen && 'rotate-180')}
              aria-hidden
            />
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-3 overflow-hidden pt-1">
          <div className="rounded-lg border bg-background/40 p-3">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <Label className="text-[13px] font-medium">{t('config.auto.label')}</Label>
                <p className="mt-0.5 text-[11px] leading-4 text-muted-foreground">
                  {t('config.auto.desc')}
                </p>
              </div>
              <Switch
                checked={autoEnabled}
                disabled={!connected}
                onCheckedChange={(v) => onAutoSet(v, intervalMin, notifyUrl.trim())}
                aria-label={t('config.auto.switch')}
              />
            </div>

            <div className="mt-4 space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <Label className="text-[13px] font-medium">{t('config.auto.interval')}</Label>
                <span
                  dir="ltr"
                  className="rounded-md bg-muted px-2 py-0.5 font-mono text-xs tabular-nums"
                >
                  {intervalMin} {t('unit.min')}
                </span>
              </div>
              <Slider
                value={[intervalMin]}
                min={5}
                max={360}
                step={5}
                disabled={running || !connected}
                onValueChange={(v) => setIntervalOverride(Array.isArray(v) ? (v[0] ?? 30) : 30)}
                onValueCommit={(v) => {
                  const next = Array.isArray(v) ? (v[0] ?? 30) : 30
                  setIntervalOverride(next)
                  if (autoEnabled) onAutoSet(true, next, notifyUrl.trim())
                }}
                aria-label={t('config.auto.interval')}
                className="w-full"
              />
              <p className="text-[11px] text-muted-foreground">
                {t('config.auto.interval.hint', { min: num(5), max: num(360) })}
              </p>
            </div>

            {/* completion webhook */}
            <div className="mt-4 space-y-2 rounded-lg border bg-card/40 p-2.5">
              <div className="flex items-center gap-1.5">
                <Bell className="size-3.5 text-muted-foreground" aria-hidden />
                <Label className="text-[12px] font-medium">{t('config.notify.label')}</Label>
              </div>
              <p className="text-[11px] leading-4 text-muted-foreground">
                {t('config.notify.desc')}
              </p>
              <div className="flex items-center gap-1.5">
                <Input
                  dir="ltr"
                  spellCheck={false}
                  className="h-8 flex-1 bg-background/60 font-mono text-xs"
                  placeholder={t('config.notify.placeholder')}
                  value={notifyUrl}
                  onChange={(e) => setNotifyUrl(e.target.value)}
                  onBlur={() => {
                    if (notifyUrl.trim() !== (autoState?.notifyUrl ?? '')) commitNotify(notifyUrl)
                  }}
                  aria-label={t('config.notify.label')}
                />
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 shrink-0 gap-1 px-2.5 text-[11px]"
                  onClick={handleNotifyTest}
                  disabled={!notifyUrl.trim() || notifyTesting || !connected}
                >
                  <Send className={cn('size-3', notifyTesting && 'animate-pulse')} aria-hidden />
                  {notifyTesting ? t('config.notify.testing') : t('config.notify.test')}
                </Button>
              </div>
              <p className="text-[10px] text-muted-foreground">{t('config.notify.hint')}</p>
            </div>

            {/* telegram notifications */}
            <div className="mt-2 space-y-2 rounded-lg border bg-card/40 p-2.5">
              <div className="flex items-center gap-1.5">
                <Bot className="size-3.5 text-muted-foreground" aria-hidden />
                <Label className="text-[12px] font-medium">{t('config.tg.label')}</Label>
                {tgConfigured ? (
                  <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-600 dark:text-emerald-400">
                    <Check className="size-2.5" aria-hidden />
                    {t('config.tg.badge')}
                  </span>
                ) : null}
                {tgConfigured ? (
                  <button
                    type="button"
                    onClick={() => void clearTelegram()}
                    className="ms-auto flex size-5 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-red-500/10 hover:text-red-500"
                    aria-label={t('config.tg.clear.aria')}
                    title={t('config.tg.clear')}
                  >
                    <X className="size-3" aria-hidden />
                  </button>
                ) : null}
              </div>
              <p className="text-[11px] leading-4 text-muted-foreground">{t('config.tg.desc')}</p>
              <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                <Input
                  dir="ltr"
                  type="password"
                  spellCheck={false}
                  autoComplete="off"
                  className="h-8 bg-background/60 font-mono text-xs"
                  placeholder={t('config.tg.token.placeholder')}
                  value={tgToken}
                  onChange={(e) => setTgToken(e.target.value)}
                  onBlur={() => void commitTelegram(tgToken, tgChatId)}
                  aria-label={t('config.tg.token')}
                />
                <Input
                  dir="ltr"
                  spellCheck={false}
                  className="h-8 bg-background/60 font-mono text-xs"
                  placeholder={t('config.tg.chat.placeholder')}
                  value={tgChatId}
                  onChange={(e) => setTgChatId(e.target.value)}
                  onBlur={() => void commitTelegram(tgToken, tgChatId)}
                  aria-label={t('config.tg.chat')}
                />
              </div>
              <div className="flex items-center justify-between gap-2">
                <p className="text-[10px] text-muted-foreground">{t('config.tg.hint')}</p>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 shrink-0 gap-1 px-2.5 text-[11px]"
                  onClick={handleTelegramTest}
                  disabled={tgTesting || !connected || (!tgConfigured && !tgToken.trim())}
                >
                  <Send className={cn('size-3', tgTesting && 'animate-pulse')} aria-hidden />
                  {tgTesting ? t('config.tg.testing') : t('config.tg.test')}
                </Button>
              </div>
              {/* digest mode — one summary message per queue batch instead of per-run spam */}
              {tgConfigured ? (
                <div className="flex items-start justify-between gap-2 rounded-md border bg-background/40 p-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 text-[11px] font-semibold">
                      <Layers className="size-3 text-teal-500" aria-hidden />
                      {t('config.tg.digest')}
                    </div>
                    <p className="mt-0.5 text-[10px] leading-4 text-muted-foreground">
                      {t('config.tg.digest.desc')}
                    </p>
                  </div>
                  <Switch
                    checked={tgDigest}
                    onCheckedChange={(v) => void toggleDigest(v)}
                    disabled={tgDigestPending || !connected}
                    aria-label={t('config.tg.digest')}
                  />
                </div>
              ) : null}
            </div>

            {/* live scheduler status */}
            <div className="mt-3 grid grid-cols-3 gap-2">
              <div className="rounded-md border bg-card/60 p-2 text-center">
                <div className="flex items-center justify-center gap-1 text-[10px] text-muted-foreground">
                  <Clock className="size-3" aria-hidden />
                  {t('config.auto.next')}
                </div>
                <div
                  dir="ltr"
                  className="mt-1 font-mono text-xs font-bold tabular-nums text-emerald-600 dark:text-emerald-400"
                >
                  {autoEnabled
                    ? countdownMs != null
                      ? formatDurationHMS(countdownMs)
                      : '…'
                    : '—'}
                </div>
              </div>
              <div className="rounded-md border bg-card/60 p-2 text-center">
                <div className="text-[10px] text-muted-foreground">{t('config.auto.runs')}</div>
                <div
                  dir="ltr"
                  className="mt-1 font-mono text-xs font-bold tabular-nums"
                >
                  {autoState ? num(autoState.runsCount) : '—'}
                </div>
              </div>
              <div className="rounded-md border bg-card/60 p-2 text-center">
                <div className="text-[10px] text-muted-foreground">{t('config.auto.last')}</div>
                <div className="mt-1 font-mono text-[11px] font-bold" dir="ltr">
                  {autoEnabled && autoState?.lastRunAt
                    ? new Date(autoState.lastRunAt).toLocaleTimeString(dateLocale, {
                        hour: '2-digit',
                        minute: '2-digit',
                      })
                    : '—'}
                </div>
              </div>
            </div>

            {autoEnabled && autoState?.running ? (
              <p className="mt-2 flex items-center gap-1.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
                <span className="size-1.5 animate-pulse rounded-full bg-emerald-500" aria-hidden />
                {t('config.auto.running')}
              </p>
            ) : null}
          </div>
        </CollapsibleContent>
      </Collapsible>

      {/* Actions */}
      <div className="mt-6 flex flex-col gap-2 sm:flex-row sm:items-center">
        <Button
          type="button"
          className="h-11 min-h-11 flex-1 border-0 bg-gradient-to-l from-emerald-600 via-emerald-500 to-teal-500 text-base font-bold text-white shadow-lg shadow-emerald-500/25 transition-all hover:from-emerald-500 hover:via-emerald-400 hover:to-teal-400 hover:shadow-emerald-500/40 disabled:opacity-50"
          onClick={handleStart}
          disabled={startDisabled}
        >
          <Play className="size-5 fill-current" aria-hidden />
          {t('config.start')}
        </Button>

        {running ? (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                type="button"
                variant="destructive"
                className="h-11 min-h-11 flex-1 text-base font-bold sm:flex-none sm:px-6"
              >
                <Square className="size-4 fill-current" aria-hidden />
                {t('config.stop')}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent dir={dir}>
              <AlertDialogHeader>
                <AlertDialogTitle>{t('config.stop.title')}</AlertDialogTitle>
                <AlertDialogDescription>
                  {t('config.stop.desc')}
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t('config.stop.cancel')}</AlertDialogCancel>
                <AlertDialogAction
                  onClick={onStop}
                  className="bg-destructive text-white hover:bg-destructive/90"
                >
                  {t('config.stop.confirm')}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        ) : null}
      </div>

      {!connected ? (
        <p className="mt-2 text-center text-[11px] text-red-500">
          {t('config.warn.offline')}
        </p>
      ) : null}
      {isCustom && rangesEmpty ? (
        <p className="mt-2 text-center text-[11px] text-amber-600 dark:text-amber-400">
          {t('config.warn.empty')}
        </p>
      ) : null}
    </div>
  )
}

/** memoized — panels only re-render when their props actually change (socket ticks re-render the page) */
export const ConfigPanel = memo(ConfigPanelInner)
