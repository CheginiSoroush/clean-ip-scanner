'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AnimatePresence, motion } from 'framer-motion'
import { KeyRound, Loader2, Lock, LockOpen, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useI18n } from '@/components/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * Optional single-user PIN lock.
 *
 *  - <LockGate />  opaque full-screen gate rendered while the lock is enabled
 *                  and this browser has no unlock cookie.
 *  - <LockSettingsButton /> header entry that opens the enable/disable dialog.
 *
 * State lives in the TanStack cache under ['lock'] so both stay in sync.
 * Server side: /api/lock + lockGuard() on every data API (see src/lib/lock.ts).
 */

interface LockQuery {
  enabled: boolean
  unlocked: boolean
}

function useLockQuery() {
  return useQuery<LockQuery>({
    queryKey: ['lock'],
    queryFn: async () => {
      const res = await fetch('/api/lock', { cache: 'no-store' })
      if (!res.ok) throw new Error('lock_state')
      return (await res.json()) as LockQuery
    },
    staleTime: 30_000,
    retry: 1,
  })
}

const PIN_RE = /^\d{4,8}$/

function shakeTrigger(shake: boolean) {
  return shake ? { x: [0, -7, 7, -5, 5, -2, 0] } : undefined
}

// ---------------------------------------------------------------- gate

export function LockGate() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const query = useLockQuery()
  const [pin, setPin] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<'wrong' | 'throttled' | null>(null)
  const [shake, setShake] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const locked = query.data?.enabled === true && query.data.unlocked !== true

  useEffect(() => {
    if (locked) {
      setError(null)
      const id = window.setTimeout(() => inputRef.current?.focus(), 250)
      return () => window.clearTimeout(id)
    }
  }, [locked])

  const submit = useCallback(async () => {
    if (busy || !PIN_RE.test(pin)) return
    setBusy(true)
    setError(null)
    try {
      const res = await fetch('/api/lock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'verify', pin }),
      })
      if (res.ok) {
        queryClient.setQueryData<LockQuery>(['lock'], { enabled: true, unlocked: true })
        setPin('')
        return
      }
      const body = (await res.json().catch(() => null)) as { reason?: string; retryAfter?: number } | null
      if (body?.reason === 'throttled') {
        setError('throttled')
      } else {
        setError('wrong')
        setShake(true)
        window.setTimeout(() => setShake(false), 450)
      }
      setPin('')
      inputRef.current?.focus()
    } catch {
      setError('wrong')
    } finally {
      setBusy(false)
    }
  }, [busy, pin, queryClient])

  if (query.isLoading || query.isError || !locked) return null

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="fixed inset-0 z-[100] flex items-center justify-center bg-background px-4"
      role="dialog"
      aria-modal="true"
      aria-label={t('lock.title')}
    >
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_35%,rgba(16,185,129,0.10),transparent_60%)]" />
      <motion.div
        animate={shakeTrigger(shake)}
        transition={{ duration: 0.4 }}
        className="relative w-full max-w-sm rounded-2xl border bg-card/80 p-6 shadow-xl backdrop-blur"
      >
        <div className="mb-5 flex flex-col items-center gap-2 text-center">
          <div className="flex size-12 items-center justify-center rounded-2xl bg-emerald-500/12 text-emerald-600 dark:text-emerald-400">
            <Lock className="size-6" aria-hidden />
          </div>
          <h1 className="text-lg font-bold">{t('lock.title')}</h1>
          <p className="text-[12.5px] text-muted-foreground">{t('lock.desc')}</p>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
          className="flex flex-col gap-3"
        >
          <Label htmlFor="lock-pin" className="sr-only">
            {t('lock.pin')}
          </Label>
          <Input
            id="lock-pin"
            ref={inputRef}
            type="password"
            inputMode="numeric"
            autoComplete="current-password"
            dir="ltr"
            maxLength={8}
            className="h-11 text-center font-mono text-lg tracking-[0.5em]"
            placeholder="••••"
            value={pin}
            onChange={(e) => {
              setPin(e.target.value.replace(/\D/g, '').slice(0, 8))
              setError(null)
            }}
            onKeyDown={(e) => {
              // explicit Enter→submit: never rely on implicit form submission
              if (e.key === 'Enter' && !e.ctrlKey && !e.altKey && !e.metaKey) {
                e.preventDefault()
                void submit()
              }
            }}
            disabled={busy}
            aria-invalid={error !== null}
            aria-describedby={error ? 'lock-error' : undefined}
          />
          <div aria-live="polite" className="min-h-4 text-center text-[11.5px]">
            {error === 'wrong' ? <span className="text-red-500">{t('lock.wrong')}</span> : null}
            {error === 'throttled' ? <span className="text-amber-500">{t('lock.tooMany')}</span> : null}
          </div>
          <Button type="submit" disabled={busy || !PIN_RE.test(pin)} className="h-11 gap-2 bg-emerald-600 text-white hover:bg-emerald-500">
            {busy ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <LockOpen className="size-4" aria-hidden />}
            {t('lock.unlock')}
          </Button>
        </form>
      </motion.div>
    </motion.div>
  )
}

// ---------------------------------------------------------------- settings dialog

export function LockSettingsButton() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const query = useLockQuery()
  const [open, setOpen] = useState(false)
  const [pin, setPin] = useState('')
  const [confirm, setConfirm] = useState('')
  const [currentPin, setCurrentPin] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const enabled = query.data?.enabled === true

  const reset = () => {
    setPin('')
    setConfirm('')
    setCurrentPin('')
    setError(null)
  }

  const call = async (payload: Record<string, string>, onOk: () => void) => {
    setBusy(true)
    setError(null)
    try {
      const res = await fetch('/api/lock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const body = (await res.json().catch(() => null)) as { ok?: boolean; reason?: string } | null
      if (res.ok && body?.ok) {
        onOk()
        setOpen(false)
        reset()
        return
      }
      if (body?.reason === 'wrong_pin') setError(t('lock.wrong'))
      else if (body?.reason === 'mismatch') setError(t('lock.mismatch'))
      else if (body?.reason === 'throttled') setError(t('lock.tooMany'))
      else setError(t('lock.wrong'))
    } catch {
      setError(t('lock.wrong'))
    } finally {
      setBusy(false)
    }
  }

  const enable = () => {
    if (!PIN_RE.test(pin)) return
    void call({ action: 'enable', pin, confirm, currentPin }, () => {
      queryClient.setQueryData<LockQuery>(['lock'], { enabled: true, unlocked: true })
      toast.success(t('lock.enabledToast'))
    })
  }

  const disable = () => {
    void call({ action: 'disable', pin: currentPin }, () => {
      queryClient.setQueryData<LockQuery>(['lock'], { enabled: false, unlocked: false })
      toast.success(t('lock.disabledToast'))
    })
  }

  return (
    <>
      <Button
        variant="ghost"
        size="icon"
        className={cn('size-9', enabled && 'text-emerald-600 dark:text-emerald-400')}
        aria-label={t('lock.aria')}
        title={t('lock.aria')}
        onClick={() => {
          reset()
          setOpen(true)
        }}
      >
        {enabled ? <ShieldCheck className="size-4" aria-hidden /> : <KeyRound className="size-4" aria-hidden />}
      </Button>

      <Dialog
        open={open}
        onOpenChange={(v) => {
          setOpen(v)
          if (!v) reset()
        }}
      >
        <DialogContent className="max-w-xs">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              {enabled ? <ShieldCheck className="size-4 text-emerald-500" aria-hidden /> : <KeyRound className="size-4" aria-hidden />}
              {enabled ? t('lock.disable') : t('lock.enable')}
            </DialogTitle>
            <DialogDescription className="sr-only">{enabled ? t('lock.disable') : t('lock.enable')}</DialogDescription>
          </DialogHeader>

          <AnimatePresence mode="wait">
            {enabled ? (
              <motion.div
                key="disable"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                className="flex flex-col gap-3"
              >
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="lock-current" className="text-[11.5px]">
                    {t('lock.currentPin')}
                  </Label>
                  <Input
                    id="lock-current"
                    type="password"
                    inputMode="numeric"
                    dir="ltr"
                    maxLength={8}
                    className="h-10 text-center font-mono tracking-[0.4em]"
                    value={currentPin}
                    onChange={(e) => setCurrentPin(e.target.value.replace(/\D/g, '').slice(0, 8))}
                    disabled={busy}
                  />
                </div>
                {error ? (
                  <p aria-live="polite" className="text-[11.5px] text-red-500">
                    {error}
                  </p>
                ) : null}
                <Button onClick={disable} disabled={busy || !PIN_RE.test(currentPin)} variant="destructive" className="h-10">
                  {busy ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <LockOpen className="size-4" aria-hidden />}
                  {t('lock.disable')}
                </Button>
              </motion.div>
            ) : (
              <motion.div
                key="enable"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                className="flex flex-col gap-3"
              >
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="lock-new" className="text-[11.5px]">
                    {t('lock.newPin')}
                  </Label>
                  <Input
                    id="lock-new"
                    type="password"
                    inputMode="numeric"
                    dir="ltr"
                    maxLength={8}
                    className="h-10 text-center font-mono tracking-[0.4em]"
                    value={pin}
                    onChange={(e) => {
                      setPin(e.target.value.replace(/\D/g, '').slice(0, 8))
                      setError(null)
                    }}
                    disabled={busy}
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="lock-confirm" className="text-[11.5px]">
                    {t('lock.confirmPin')}
                  </Label>
                  <Input
                    id="lock-confirm"
                    type="password"
                    inputMode="numeric"
                    dir="ltr"
                    maxLength={8}
                    className="h-10 text-center font-mono tracking-[0.4em]"
                    value={confirm}
                    onChange={(e) => {
                      setConfirm(e.target.value.replace(/\D/g, '').slice(0, 8))
                      setError(null)
                    }}
                    disabled={busy}
                  />
                </div>
                {error ? (
                  <p aria-live="polite" className="text-[11.5px] text-red-500">
                    {error}
                  </p>
                ) : null}
                <Button
                  onClick={enable}
                  disabled={busy || !PIN_RE.test(pin) || pin !== confirm}
                  className="h-10 bg-emerald-600 text-white hover:bg-emerald-500"
                >
                  {busy ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <Lock className="size-4" aria-hidden />}
                  {t('lock.enable')}
                </Button>
              </motion.div>
            )}
          </AnimatePresence>
        </DialogContent>
      </Dialog>
    </>
  )
}
