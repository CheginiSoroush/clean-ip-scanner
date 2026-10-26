'use client'

/**
 * QueuePanel — multi-CDN scan queue (engine-side).
 * Items run automatically, one by one, whenever the engine is idle.
 * Desktop: HTML5 drag & drop reordering (grip handle) · Touch: chevron buttons.
 */

import { useCallback, memo, useRef, useState } from 'react'
import {
  AlertCircle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Clock,
  GripVertical,
  ListPlus,
  ListTodo,
  Loader2,
  Pencil,
  Pause,
  Play,
  SkipForward,
  Trash2,
  X,
} from 'lucide-react'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { CDN_PRESETS } from '@/lib/cdn-presets'
import { useI18n } from '@/components/i18n-provider'
import type { QueueItem, QueueItemStatus, ScanConfig, ScanQueueState } from '@/lib/scan-protocol'
import { formatBytesPerSec } from '@/lib/scan-protocol'
import { cn } from '@/lib/utils'

interface QueuePanelProps {
  connected: boolean
  queueState: ScanQueueState | null
  /** add the current (sanitized) config — page.tsx owns validation + toasts */
  onAdd: () => void
  onRemove: (id: string) => void
  onClear: () => void
  /** swap a waiting item with its nearest waiting neighbour (dir -1 = earlier, +1 = later) */
  onMove: (id: string, dir: -1 | 1) => void
  /** drag & drop: move a waiting item to the given array index (engine-clamped) */
  onReorder: (id: string, index: number) => void
  /** enable/disable a waiting item — the processor skips disabled ones */
  onToggle: (id: string) => void
  /** edit a waiting item in place (label + partial config, engine re-clamps) — resolves false on failure */
  onEdit: (id: string, patch: { label?: string; config?: Partial<ScanConfig> }) => Promise<boolean>
}

const STATUS_STYLE: Record<QueueItemStatus, { dot: string; badge: string; icon: typeof Clock }> = {
  waiting: {
    dot: 'bg-zinc-400',
    badge: 'bg-zinc-500/10 text-zinc-600 dark:text-zinc-300',
    icon: Clock,
  },
  running: {
    dot: 'bg-emerald-500',
    badge: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
    icon: Loader2,
  },
  done: {
    dot: 'bg-emerald-500',
    badge: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
    icon: CheckCircle2,
  },
  skipped: {
    dot: 'bg-amber-500',
    badge: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
    icon: SkipForward,
  },
  error: {
    dot: 'bg-red-500',
    badge: 'bg-red-500/10 text-red-600 dark:text-red-400',
    icon: AlertCircle,
  },
}

function presetAccent(preset: string): string {
  const p = CDN_PRESETS.find((x) => x.id === preset)
  if (!p) return 'bg-zinc-400'
  return {
    orange: 'bg-orange-500',
    emerald: 'bg-emerald-500',
    rose: 'bg-rose-500',
    violet: 'bg-violet-500',
    cyan: 'bg-cyan-500',
    teal: 'bg-teal-500',
    amber: 'bg-amber-500',
  }[p.accent] ?? 'bg-zinc-400'
}

function QueueRow({
  item,
  index,
  dragging,
  dropHint,
  onDragStartItem,
  onDragEndItem,
  onDragOverItem,
  onRemove,
  onMove,
  onToggle,
  onEdit,
}: {
  item: QueueItem
  index: number
  /** this row is the currently dragged one */
  dragging: boolean
  /** insertion indicator on this row: 'before' | 'after' | null */
  dropHint: 'before' | 'after' | null
  onDragStartItem: (id: string) => void
  onDragEndItem: () => void
  onDragOverItem: (e: React.DragEvent, index: number) => void
  onRemove: (id: string) => void
  onMove: (id: string, dir: -1 | 1) => void
  onToggle: (id: string) => void
  onEdit: (id: string, patch: { label?: string; config?: Partial<ScanConfig> }) => Promise<boolean>
}) {
  const { t, num, dir } = useI18n()
  const st = STATUS_STYLE[item.status] ?? STATUS_STYLE.waiting
  const Icon = st.icon
  const removable = item.status !== 'running'
  const waiting = item.status === 'waiting'
  const enabled = item.enabled !== false

  // ----- inline edit state (waiting items only) -----
  const [editing, setEditing] = useState(false)
  const [editLabel, setEditLabel] = useState(item.label)
  const [editPort, setEditPort] = useState(String(item.config.port))
  const [editIps, setEditIps] = useState(String(item.config.maxIPs))
  const [editTests, setEditTests] = useState(String(item.config.speedTestCount))
  const [saving, setSaving] = useState(false)

  const openEdit = useCallback(() => {
    setEditLabel(item.label)
    setEditPort(String(item.config.port))
    setEditIps(String(item.config.maxIPs))
    setEditTests(String(item.config.speedTestCount))
    setEditing(true)
  }, [item.label, item.config.port, item.config.maxIPs, item.config.speedTestCount])

  const saveEdit = useCallback(async () => {
    setSaving(true)
    const ok = await onEdit(item.id, {
      label: editLabel.trim() !== item.label ? editLabel.trim() : undefined,
      config: {
        port: Math.min(65535, Math.max(1, Number(editPort) || item.config.port)),
        maxIPs: Math.min(200000, Math.max(10, Number(editIps) || item.config.maxIPs)),
        speedTestCount: Math.min(30, Math.max(1, Number(editTests) || item.config.speedTestCount)),
      },
    })
    setSaving(false)
    if (ok) setEditing(false)
  }, [onEdit, item.id, item.label, item.config.port, item.config.maxIPs, item.config.speedTestCount, editLabel, editPort, editIps, editTests])

  if (editing && waiting) {
    return (
      <li
        aria-label={t('queue.item.aria', { label: item.label })}
        className="flex flex-col gap-2.5 rounded-lg border border-teal-500/40 bg-teal-500/[0.04] p-2.5 ring-1 ring-teal-500/20"
      >
        <div className="flex items-center gap-1.5">
          <Pencil className="size-3.5 text-teal-600 dark:text-teal-400" aria-hidden />
          <span className="text-[12px] font-bold text-teal-700 dark:text-teal-300">{t('queue.edit.title')}</span>
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <label className="col-span-2 flex flex-col gap-1 sm:col-span-4">
            <span className="text-[10.5px] font-medium text-muted-foreground">{t('queue.edit.label')}</span>
            <Input
              value={editLabel}
              onChange={(e) => setEditLabel(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void saveEdit()
                if (e.key === 'Escape') setEditing(false)
              }}
              className="h-8 text-[12.5px]"
              maxLength={80}
              autoFocus
              aria-label={t('queue.edit.label')}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[10.5px] font-medium text-muted-foreground">{t('queue.edit.port')}</span>
            <Input
              dir="ltr"
              type="number"
              min={1}
              max={65535}
              value={editPort}
              onChange={(e) => setEditPort(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void saveEdit()
                if (e.key === 'Escape') setEditing(false)
              }}
              className="h-8 font-mono text-[12px]"
              aria-label={t('queue.edit.port')}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[10.5px] font-medium text-muted-foreground">{t('queue.edit.ips')}</span>
            <Input
              dir="ltr"
              type="number"
              min={10}
              max={200000}
              value={editIps}
              onChange={(e) => setEditIps(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void saveEdit()
                if (e.key === 'Escape') setEditing(false)
              }}
              className="h-8 font-mono text-[12px]"
              aria-label={t('queue.edit.ips')}
            />
          </label>
          <label className="col-span-2 flex flex-col gap-1">
            <span className="text-[10.5px] font-medium text-muted-foreground">{t('queue.edit.tests')}</span>
            <Input
              dir="ltr"
              type="number"
              min={1}
              max={30}
              value={editTests}
              onChange={(e) => setEditTests(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void saveEdit()
                if (e.key === 'Escape') setEditing(false)
              }}
              className="h-8 font-mono text-[12px]"
              aria-label={t('queue.edit.tests')}
            />
          </label>
        </div>
        <div className="flex items-center justify-end gap-2">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-8 px-3 text-muted-foreground"
            onClick={() => setEditing(false)}
            disabled={saving}
          >
            <X className="size-3.5" aria-hidden />
            {t('queue.edit.cancel')}
          </Button>
          <Button
            type="button"
            size="sm"
            className="h-8 gap-1.5 bg-teal-600 px-3 text-white hover:bg-teal-700"
            onClick={() => void saveEdit()}
            disabled={saving}
          >
            {saving ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <Check className="size-3.5" aria-hidden />}
            {t('queue.edit.save')}
          </Button>
        </div>
      </li>
    )
  }

  return (
    <li
      draggable={waiting}
      onDragStart={(e) => {
        if (!waiting) return
        e.dataTransfer.effectAllowed = 'move'
        e.dataTransfer.setData('text/plain', item.id)
        onDragStartItem(item.id)
      }}
      onDragEnd={onDragEndItem}
      onDragOver={(e) => onDragOverItem(e, index)}
      aria-label={t('queue.item.aria', { label: item.label })}
      className={cn(
        'group relative flex items-center gap-2.5 rounded-lg border bg-card/50 p-2.5 transition-all',
        item.status === 'running'
          ? 'border-emerald-500/40 ring-1 ring-emerald-500/30 shadow-md shadow-emerald-500/10'
          : 'border-border/70 hover:border-emerald-500/25',
        waiting && !enabled && 'border-dashed opacity-65 hover:opacity-100',
        waiting && 'cursor-grab active:cursor-grabbing',
        dragging && 'opacity-40',
        dropHint === 'before' && 'border-t-2 border-t-teal-500',
        dropHint === 'after' && 'border-b-2 border-b-teal-500',
      )}
    >
      {/* running shimmer strip */}
      {item.status === 'running' ? (
        <span
          aria-hidden
          className="absolute inset-y-1 start-1 w-1 rounded-full bg-gradient-to-b from-emerald-400 to-teal-500"
        />
      ) : null}

      {/* grip handle — drag affordance (waiting only) */}
      {waiting ? (
        <span
          aria-hidden
          className="flex size-6 shrink-0 cursor-grab items-center justify-center rounded text-muted-foreground/40 transition-colors group-hover:text-muted-foreground active:cursor-grabbing"
        >
          <GripVertical className="size-4" />
        </span>
      ) : null}

      <span
        className={cn(
          'flex size-7 shrink-0 items-center justify-center rounded-md',
          item.status === 'running'
            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
            : waiting && !enabled
              ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
              : 'bg-muted text-muted-foreground',
        )}
        aria-hidden
      >
        {waiting && !enabled ? (
          <Pause className="size-3.5" />
        ) : (
          <Icon className={cn('size-3.5', item.status === 'running' && 'animate-spin')} />
        )}
      </span>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span
            className={cn('size-1.5 shrink-0 rounded-full', presetAccent(item.config.preset))}
            aria-hidden
          />
          <span className={cn('truncate text-[12.5px] font-semibold', waiting && !enabled && 'line-through decoration-amber-500/50')}>
            {item.label}
          </span>
        </div>
        <div dir="ltr" className="mt-0.5 flex items-center gap-2 font-mono text-[10.5px] text-muted-foreground">
          <span>:{num(item.config.port)}</span>
          <span aria-hidden>·</span>
          <span>{num(item.config.maxIPs)} IPs</span>
          <span aria-hidden>·</span>
          <span>×{num(item.config.speedTestCount)}</span>
        </div>
        {item.status === 'done' && item.result ? (
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10.5px]">
            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-1.5 py-0.5 font-medium text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 className="size-2.5" aria-hidden />
              {t('queue.result.clean', { n: num(item.result.clean) })}
            </span>
            {item.result.bestIp && (item.result.bestSpeedBps ?? 0) > 0 ? (
              <span dir="ltr" className="truncate font-mono text-muted-foreground">
                {item.result.bestIp} · {formatBytesPerSec(item.result.bestSpeedBps ?? 0)}
              </span>
            ) : null}
          </div>
        ) : null}
      </div>

      <span
        className={cn(
          'inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold',
          waiting && !enabled
            ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
            : st.badge,
        )}
      >
        {waiting && !enabled ? t('queue.status.paused') : t(`queue.status.${item.status}` as const)}
      </span>

      {/* reorder buttons — always visible on touch, hover-revealed on desktop */}
      {waiting ? (
        <span
          role="group"
          aria-label={t('queue.move.group')}
          className="flex shrink-0 flex-col items-center rounded-md border border-border/60 max-sm:opacity-100 sm:opacity-0 sm:transition-opacity sm:group-hover:opacity-100 sm:focus-within:opacity-100"
        >
          <button
            type="button"
            onClick={() => onMove(item.id, -1)}
            aria-label={t('queue.move.up.aria', { label: item.label })}
            className="flex h-5 w-7 items-center justify-center rounded-t-md text-muted-foreground transition-colors hover:bg-emerald-500/10 hover:text-emerald-600 dark:hover:text-emerald-400"
          >
            <ChevronUp className="size-3.5" aria-hidden />
          </button>
          <span aria-hidden className="h-px w-5 bg-border/70" />
          <button
            type="button"
            onClick={() => onMove(item.id, 1)}
            aria-label={t('queue.move.down.aria', { label: item.label })}
            className="flex h-5 w-7 items-center justify-center rounded-b-md text-muted-foreground transition-colors hover:bg-emerald-500/10 hover:text-emerald-600 dark:hover:text-emerald-400"
          >
            <ChevronDown className="size-3.5" aria-hidden />
          </button>
        </span>
      ) : null}

      {waiting ? (
        <button
          type="button"
          onClick={() => onToggle(item.id)}
          aria-label={enabled ? t('queue.pause.aria', { label: item.label }) : t('queue.resume.aria', { label: item.label })}
          title={enabled ? t('queue.pause.aria', { label: item.label }) : t('queue.resume.aria', { label: item.label })}
          className={cn(
            'flex size-8 shrink-0 items-center justify-center rounded-md transition-all max-sm:opacity-100 sm:size-7 sm:opacity-60 sm:group-hover:opacity-100 sm:focus-visible:opacity-100',
            enabled
              ? 'text-muted-foreground hover:bg-amber-500/10 hover:text-amber-500'
              : 'text-amber-500 hover:bg-emerald-500/10 hover:text-emerald-500',
          )}
        >
          {enabled ? <Pause className="size-4 sm:size-3.5" aria-hidden /> : <Play className="size-4 sm:size-3.5" aria-hidden />}
        </button>
      ) : null}

      {waiting ? (
        <button
          type="button"
          onClick={openEdit}
          aria-label={t('queue.edit.aria', { label: item.label })}
          title={t('queue.edit.aria', { label: item.label })}
          className="flex size-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-all hover:bg-teal-500/10 hover:text-teal-600 dark:hover:text-teal-400 max-sm:opacity-100 sm:size-7 sm:opacity-60 sm:group-hover:opacity-100 sm:focus-visible:opacity-100"
        >
          <Pencil className="size-4 sm:size-3.5" aria-hidden />
        </button>
      ) : null}

      {removable ? (
        <button
          type="button"
          onClick={() => onRemove(item.id)}
          aria-label={t('queue.remove.aria', { label: item.label })}
          className="flex size-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-all hover:bg-red-500/10 hover:text-red-500 max-sm:opacity-100 sm:size-7 sm:opacity-60 sm:group-hover:opacity-100"
        >
          <X className="size-4 sm:size-3.5" aria-hidden />
        </button>
      ) : (
        <ChevronRight className={cn('size-3.5 shrink-0 text-emerald-500', dir === 'rtl' && 'rotate-180')} aria-hidden />
      )}
    </li>
  )
}

function QueuePanelInner({ connected, queueState, onAdd, onRemove, onClear, onMove, onReorder, onToggle, onEdit }: QueuePanelProps) {
  const { t, num } = useI18n()
  const items = queueState?.items ?? []
  const waiting = items.filter((i) => i.status === 'waiting').length

  // ----- drag & drop state -----
  const dragIdRef = useRef<string | null>(null)
  const [dragId, setDragId] = useState<string | null>(null)
  const [dropHint, setDropHint] = useState<{ index: number; at: 'before' | 'after' } | null>(null)
  const dragCounter = useRef(0)

  const handleDragStart = useCallback((id: string) => {
    dragIdRef.current = id
    setDragId(id)
  }, [])

  const handleDragEnd = useCallback(() => {
    dragIdRef.current = null
    setDragId(null)
    setDropHint(null)
    dragCounter.current = 0
  }, [])

  const handleDragOverRow = useCallback(
    (e: React.DragEvent, index: number) => {
      const dragged = dragIdRef.current
      if (!dragged) return
      e.preventDefault()
      e.dataTransfer.dropEffect = 'move'
      const rect = e.currentTarget.getBoundingClientRect()
      const after = e.clientY - rect.top > rect.height / 2
      setDropHint({ index, at: after ? 'after' : 'before' })
    },
    [],
  )

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      const dragged = dragIdRef.current
      const hint = dropHint
      handleDragEnd()
      if (!dragged || !hint) return
      // convert (index, before/after) into the engine's post-removal insert index
      const dragIdx = items.findIndex((i) => i.id === dragged)
      if (dragIdx < 0) return
      let pos = hint.at === 'after' ? hint.index + 1 : hint.index
      if (dragIdx < pos) pos -= 1
      if (pos === dragIdx) return
      onReorder(dragged, pos)
    },
    [dropHint, handleDragEnd, items, onReorder],
  )

  return (
    <section
      aria-label={t('queue.title')}
      className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6"
    >
      {/* header */}
      <div className="flex items-center gap-2">
        <span className="flex size-8 items-center justify-center rounded-lg bg-teal-500/10 text-teal-600 dark:text-teal-400">
          <ListTodo className="size-4" aria-hidden />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold">{t('queue.title')}</h2>
            {items.length > 0 ? (
              <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] font-semibold text-muted-foreground">
                {t('queue.badge.count', { n: num(items.length) })}
              </span>
            ) : null}
            {queueState?.running ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-600 dark:text-emerald-400">
                <span className="size-1.5 animate-pulse rounded-full bg-emerald-500" aria-hidden />
                {t('queue.status.running')}
              </span>
            ) : null}
          </div>
          <p className="truncate text-[11px] text-muted-foreground">{t('queue.desc')}</p>
        </div>
      </div>

      {/* list */}
      <div className="mt-4">
        {items.length === 0 ? (
          <div className="flex flex-col items-center gap-1.5 rounded-lg border border-dashed py-6 text-center">
            <ListTodo className="size-5 text-muted-foreground/50" aria-hidden />
            <p className="px-4 text-[12px] text-muted-foreground">{t('queue.empty')}</p>
          </div>
        ) : (
          <ul
            className="scrollbar-thin max-h-64 space-y-2 overflow-y-auto pe-0.5"
            onDrop={handleDrop}
            onDragOver={(e) => {
              // keep the drag alive over the list gaps
              if (dragIdRef.current) e.preventDefault()
            }}
          >
            {items.map((item, index) => (
              <QueueRow
                key={item.id}
                item={item}
                index={index}
                dragging={dragId === item.id}
                dropHint={
                  dropHint && dropHint.index === index && dragId !== item.id ? dropHint.at : null
                }
                onDragStartItem={handleDragStart}
                onDragEndItem={handleDragEnd}
                onDragOverItem={handleDragOverRow}
                onRemove={onRemove}
                onMove={onMove}
                onToggle={onToggle}
                onEdit={onEdit}
              />
            ))}
          </ul>
        )}
      </div>

      {/* actions */}
      <div className="mt-4 flex items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-9 flex-1 gap-1.5 border-teal-500/30 text-teal-700 hover:bg-teal-500/10 hover:text-teal-700 dark:text-teal-400 dark:hover:text-teal-300"
          onClick={onAdd}
          disabled={!connected}
          aria-label={t('queue.add.aria')}
        >
          <ListPlus className="size-4" aria-hidden />
          {t('queue.add')}
          {waiting > 0 ? (
            <span className="rounded-full bg-teal-500/15 px-1.5 text-[10px] font-bold">
              +{num(waiting)}
            </span>
          ) : null}
        </Button>

        {items.length > 0 ? (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-9 gap-1.5 px-3 text-muted-foreground hover:bg-red-500/10 hover:text-red-500"
              >
                <Trash2 className="size-3.5" aria-hidden />
                {t('queue.clear')}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent dir="rtl">
              <AlertDialogHeader>
                <AlertDialogTitle>{t('queue.clear.title')}</AlertDialogTitle>
                <AlertDialogDescription>{t('queue.clear.desc')}</AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t('queue.cancel')}</AlertDialogCancel>
                <AlertDialogAction
                  onClick={onClear}
                  className="bg-destructive text-white hover:bg-destructive/90"
                >
                  {t('queue.clear.confirm')}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        ) : null}
      </div>

      <p className="mt-2.5 flex items-start gap-1.5 text-[10.5px] leading-4 text-muted-foreground">
        <Clock className="mt-0.5 size-3 shrink-0" aria-hidden />
        {t('queue.hint')}
      </p>
    </section>
  )
}

/** memoized — skips re-render on socket RTT/log ticks when props are unchanged */
export const QueuePanel = memo(QueuePanelInner)
