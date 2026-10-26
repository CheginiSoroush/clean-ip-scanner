'use client'

import { Radar, Github, Sun, Moon, Loader2, Volume2, VolumeX, Languages } from 'lucide-react'
import { useSyncExternalStore } from 'react'
import { useTheme } from 'next-themes'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { isSoundEnabled, setSoundEnabled, subscribeSound } from '@/lib/sound'
import { LockSettingsButton } from '@/components/scan/lock'
import { useI18n } from '@/components/i18n-provider'
import { cn } from '@/lib/utils'

interface HeaderProps {
  connected: boolean
  rtt: number | null
}

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme()
  const { t } = useI18n()

  return (
    <Button
      variant="ghost"
      size="icon"
      className="size-9"
      aria-label={t('header.theme.toggle')}
      onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}
    >
      <Sun className="size-4 dark:hidden" />
      <Moon className="hidden size-4 dark:block" />
    </Button>
  )
}

function SoundToggle() {
  // store-backed so toggles persist + sync across tabs, hydration-safe
  const enabled = useSyncExternalStore(subscribeSound, isSoundEnabled, () => true)
  const { t } = useI18n()

  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn('size-9', enabled && 'text-emerald-600 dark:text-emerald-400')}
      aria-label={enabled ? t('header.sound.on') : t('header.sound.off')}
      title={enabled ? t('header.sound.on.title') : t('header.sound.off.title')}
      onClick={() => setSoundEnabled(!enabled)}
    >
      {enabled ? <Volume2 className="size-4" /> : <VolumeX className="size-4" />}
    </Button>
  )
}

function LangToggle() {
  const { lang, setLang, t } = useI18n()

  return (
    <Button
      variant="ghost"
      size="icon"
      className="group relative size-9"
      aria-label={t('header.lang.toggle')}
      title={t('header.lang.toggle')}
      onClick={() => setLang(lang === 'fa' ? 'en' : 'fa')}
    >
      <Languages className="size-4 transition-transform duration-300 group-hover:-rotate-12" />
      <span className="absolute -bottom-0.5 -end-0.5 rounded-sm bg-emerald-500 px-1 font-mono text-[8px] font-bold leading-3.5 text-white shadow-sm">
        {lang === 'fa' ? 'EN' : 'فا'}
      </span>
    </Button>
  )
}

export function Header({ connected, rtt }: HeaderProps) {
  const { t } = useI18n()

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/60 bg-background/70 backdrop-blur-xl supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between gap-3 px-4">
        {/* Brand */}
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-teal-600 text-white shadow-lg shadow-emerald-500/20">
            <Radar className="size-5" aria-hidden />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1
                dir="ltr"
                className="truncate bg-gradient-to-l from-emerald-600 via-emerald-500 to-teal-500 bg-clip-text text-sm font-bold text-transparent sm:text-lg dark:from-emerald-400 dark:via-emerald-300 dark:to-teal-300"
              >
                Clean IP Scanner
              </h1>
              <Badge className="hidden border-emerald-500/30 bg-emerald-500/10 text-emerald-600 sm:inline-flex dark:text-emerald-400">
                Web Edition
              </Badge>
            </div>
            <p className="hidden text-xs text-muted-foreground sm:block">
              {t('header.subtitle')}
            </p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex shrink-0 items-center gap-1.5 sm:gap-2">
          <div
            className="flex items-center gap-2 rounded-full border border-border/70 bg-card/60 px-3 py-1.5"
            dir="ltr"
            role="status"
            aria-label={connected ? t('header.conn.ok') : t('header.conn.off')}
          >
            <span className="relative flex size-2.5">
              {connected && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-60" />
              )}
              <span
                className={cn(
                  'relative inline-flex size-2.5 rounded-full',
                  connected ? 'bg-emerald-500' : 'bg-red-500'
                )}
              />
            </span>
            <span className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground">
              {!connected ? (
                <Loader2 className="size-3 animate-spin" aria-hidden />
              ) : null}
              {connected ? (rtt != null ? `${rtt} ms` : '…') : 'offline'}
            </span>
          </div>

          <Button variant="ghost" size="icon" className="hidden size-9 sm:inline-flex" asChild>
            <a
              href="https://github.com/CheginiSoroush/clean-ip-scanner"
              target="_blank"
              rel="noreferrer"
              aria-label={t('header.github')}
            >
              <Github className="size-4" />
            </a>
          </Button>

          <LangToggle />

          <SoundToggle />

          <LockSettingsButton />

          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
