'use client'

import { useMemo, useRef, useState } from 'react'
import { Check, Download, Gauge, RotateCcw, SlidersHorizontal, Sparkles, Upload } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Slider } from '@/components/ui/slider'
import { cn } from '@/lib/utils'
import {
  clampWeights,
  computeIpScores,
  rankScores,
  scoreBand,
  SCORE_BAND_HEX,
  SCORE_WEIGHT_PRESETS,
  WEIGHT_SLIDER_MAX,
  type ScoreInput,
  type ScoreWeights,
} from '@/lib/ip-score'
import { getScoreWeights, setScoreWeights, useScoreWeights } from '@/lib/score-weights'
import { csvFileStamp } from '@/lib/csv'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'

const WEIGHT_KEYS = ['grade', 'tls', 'loss', 'speed', 'stab'] as const

const WEIGHT_LABELS: Record<(typeof WEIGHT_KEYS)[number], DictKey> = {
  grade: 'results.smart.bd.grade',
  tls: 'tune.w.tls',
  loss: 'results.smart.bd.loss',
  speed: 'results.smart.bd.speed',
  stab: 'results.smart.bd.stab',
}

export interface ScoreTuningDialogProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  /** current ranked results (live scan) for the what-if preview */
  inputs: ScoreInput[]
  probes: Record<string, { grade?: 'excellent' | 'good' | 'weak' | 'fail'; tlsMs?: number | null; ok: boolean }>
  favorites: Set<string>
}

export function ScoreTuningDialog({ open, onOpenChange, inputs, probes, favorites }: ScoreTuningDialogProps) {
  const { t, num, dir, lang } = useI18n()
  const weights = useScoreWeights()
  const [presetKey, setPresetKey] = useState<string | null>('default')
  const fileRef = useRef<HTMLInputElement>(null)

  const fmt = useMemo(
    () => ({
      bytesPerSec: (bps: number) => `${(bps / (1024 * 1024)).toFixed(1)} MB/s`,
      latency: (ms: number) => `${Math.round(ms)} ms`,
    }),
    [],
  )

  // live what-if preview: recompute the top-3 with the current slider values
  const preview = useMemo(() => {
    if (inputs.length === 0) return []
    const scores = computeIpScores(inputs.slice(0, 30), probes, favorites, fmt, weights)
    return rankScores(scores).slice(0, 3)
  }, [inputs, probes, favorites, fmt, weights])

  const applyPreset = (key: string) => {
    const p = SCORE_WEIGHT_PRESETS[key]
    if (!p) return
    setPresetKey(key)
    setScoreWeights(p.w)
  }

  const setKey = (k: (typeof WEIGHT_KEYS)[number], v: number) => {
    setPresetKey(null)
    setScoreWeights({ ...getScoreWeights(), [k]: v })
  }

  const total = WEIGHT_KEYS.reduce((s, k) => s + weights[k], 0)

  // ---- v7.8 — weight-preset import / export (portable JSON, same shape the store persists) ----
  const exportWeights = () => {
    try {
      const payload = {
        app: 'clean-ip-scanner',
        kind: 'score-weights',
        version: 1,
        exportedAt: new Date().toISOString(),
        weights: getScoreWeights(),
      }
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `cis-score-weights-${csvFileStamp()}.json`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      toast.success(t('tune.export.ok'))
    } catch {
      toast.error(t('tune.export.fail'))
    }
  }

  const onImportFile = async (file: File) => {
    try {
      const parsed = JSON.parse(await file.text()) as {
        kind?: string
        weights?: Partial<ScoreWeights>
      }
      const raw = parsed && typeof parsed === 'object' && parsed.kind === 'score-weights' ? parsed.weights : parsed
      const w = raw as Partial<ScoreWeights> | null | undefined
      // strict: every component must be present and finite — no silent half-presets
      if (!w || typeof w !== 'object' || !WEIGHT_KEYS.every((k) => Number.isFinite(Number(w[k])))) {
        throw new Error('invalid preset')
      }
      setScoreWeights(clampWeights(w))
      setPresetKey(null)
      toast.success(t('tune.import.ok'))
    } catch {
      toast.error(t('tune.import.fail'))
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md overflow-x-hidden" dir={dir}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
              <SlidersHorizontal className="size-4" aria-hidden />
            </span>
            {t('tune.title')}
          </DialogTitle>
          <DialogDescription>{t('tune.desc')}</DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
          {/* presets */}
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(SCORE_WEIGHT_PRESETS).map(([key, p]) => (
              <button
                key={key}
                type="button"
                onClick={() => applyPreset(key)}
                className={cn(
                  'inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-medium transition-colors',
                  presetKey === key
                    ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                    : 'border-border bg-background/60 text-muted-foreground hover:border-emerald-500/40 hover:text-emerald-600',
                )}
              >
                {presetKey === key ? <Check className="size-3" aria-hidden /> : <Gauge className="size-3" aria-hidden />}
                {lang === 'fa' ? p.label : p.labelEn}
              </button>
            ))}
          </div>

          {/* sliders */}
          <div className="grid gap-3">
            {WEIGHT_KEYS.map((k) => (
              <div key={k} className="flex items-center gap-3">
                <span className="w-20 shrink-0 text-xs font-medium">{t(WEIGHT_LABELS[k])}</span>
                <Slider
                  value={[weights[k]]}
                  min={0}
                  max={WEIGHT_SLIDER_MAX}
                  step={1}
                  onValueChange={([v]) => setKey(k, v)}
                  aria-label={t(WEIGHT_LABELS[k])}
                  className="flex-1"
                />
                <span className="w-8 shrink-0 text-end font-mono text-xs font-bold text-emerald-600 dark:text-emerald-400" dir="ltr">
                  {num(weights[k])}
                </span>
              </div>
            ))}
          </div>

          {/* total weight indicator */}
          <div className="flex items-center justify-between rounded-lg border border-border bg-background/50 px-3 py-1.5 text-[11px]">
            <span className="text-muted-foreground">{t('tune.total')}</span>
            <span
              className={cn('font-mono font-bold', total === 100 ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400')}
              dir="ltr"
            >
              {num(total)} / ۱۰۰
            </span>
          </div>

          {/* live what-if preview */}
          {preview.length > 0 ? (
            <div className="rounded-lg border border-teal-500/25 bg-teal-500/[0.04] p-3">
              <p className="mb-1.5 flex items-center gap-1 text-[11px] font-semibold text-teal-700 dark:text-teal-300">
                <Sparkles className="size-3" aria-hidden />
                {t('tune.preview')}
              </p>
              <div className="flex flex-wrap gap-1.5">
                {preview.map((s) => (
                  <span
                    key={s.ip}
                    className="inline-flex items-center gap-1 rounded-md border border-border bg-background/60 px-1.5 py-0.5 font-mono text-[10px]"
                    dir="ltr"
                  >
                    <span>{s.ip}</span>
                    <span style={{ color: SCORE_BAND_HEX[scoreBand(s.score)] }}>{num(Math.round(s.score))}</span>
                  </span>
                ))}
              </div>
            </div>
          ) : null}

          {/* v7.8 — portable preset import / export */}
          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="sm"
              className="h-8 flex-1 gap-1.5 text-[11px]"
              onClick={exportWeights}
              aria-label={t('tune.export')}
            >
              <Download className="size-3.5" aria-hidden />
              {t('tune.export')}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-8 flex-1 gap-1.5 text-[11px]"
              onClick={() => fileRef.current?.click()}
              aria-label={t('tune.import')}
            >
              <Upload className="size-3.5" aria-hidden />
              {t('tune.import')}
            </Button>
            <input
              ref={fileRef}
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) void onImportFile(f)
                e.target.value = ''
              }}
            />
          </div>

          {/* reset */}
          <div className="flex items-center justify-between">
            <Button
              variant="ghost"
              size="sm"
              className="h-8 gap-1.5 text-muted-foreground"
              onClick={() => {
                setPresetKey('default')
                setScoreWeights({ grade: 34, tls: 24, loss: 16, speed: 16, stab: 10 })
              }}
            >
              <RotateCcw className="size-3.5" aria-hidden />
              {t('tune.reset')}
            </Button>
            <span className="text-[10px] text-muted-foreground">{t('tune.persist')}</span>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
