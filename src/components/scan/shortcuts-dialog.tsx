'use client'

/**
 * ShortcutsDialog — keyboard shortcut reference (opens with "?").
 */

import { Keyboard } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Kbd } from '@/components/ui/kbd'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'

const SHORTCUTS: { keys: string[]; labelKey: DictKey }[] = [
  { keys: ['Ctrl', 'Enter'], labelKey: 'sc.start' },
  { keys: ['Ctrl', '.'], labelKey: 'sc.stop' },
  { keys: ['Alt', '1'], labelKey: 'sc.tab.live' },
  { keys: ['Alt', '2'], labelKey: 'sc.tab.history' },
  { keys: ['Alt', '3'], labelKey: 'sc.tab.favorites' },
  { keys: ['Alt', 'B'], labelKey: 'sc.batch' },
  { keys: ['?'], labelKey: 'sc.help' },
  { keys: ['Esc'], labelKey: 'sc.close' },
]

export function ShortcutsDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t, dir } = useI18n()

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent dir={dir} className="max-w-sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span className="flex size-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
              <Keyboard className="size-4" aria-hidden />
            </span>
            {t('sc.title')}
          </DialogTitle>
          <DialogDescription>
            {t('sc.desc')}
          </DialogDescription>
        </DialogHeader>
        <ul className="space-y-2">
          {SHORTCUTS.map((s) => (
            <li
              key={s.labelKey}
              className="flex items-center justify-between rounded-lg border bg-background/40 px-3 py-2"
            >
              <span className="text-xs">{t(s.labelKey)}</span>
              <span className="flex items-center gap-1" dir="ltr">
                {s.keys.map((k) => (
                  <Kbd key={k}>{k}</Kbd>
                ))}
              </span>
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  )
}
