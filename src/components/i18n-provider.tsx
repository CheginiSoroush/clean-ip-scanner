'use client'

/**
 * I18nProvider — locale context (fa default / en), hydration-safe.
 * - persists the choice in localStorage ('cis-lang'), synced across tabs
 * - keeps <html lang dir> in sync for correct RTL/LTR layout
 * - exposes t() (interpolated dictionary lookup), num() (locale digits)
 *   and date helpers so components never hard-code Persian formatting
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
  type ReactNode,
} from 'react'
import { DICT, interpolate, LANG_META, type DictKey, type Lang } from '@/lib/i18n'

const STORAGE_KEY = 'cis-lang'

// ---------- tiny external lang store (localStorage-backed, cross-tab synced) ----------
let cachedLang: Lang | null = null
const langSubs = new Set<() => void>()

function readLang(): Lang {
  if (cachedLang) return cachedLang
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    if (stored === 'fa' || stored === 'en') cachedLang = stored
  } catch {
    /* private mode etc. */
  }
  return cachedLang ?? 'fa'
}

function subscribeLang(cb: () => void): () => void {
  langSubs.add(cb)
  const onStorage = (e: StorageEvent) => {
    if (e.key === STORAGE_KEY) cb()
  }
  window.addEventListener('storage', onStorage)
  return () => {
    langSubs.delete(cb)
    window.removeEventListener('storage', onStorage)
  }
}

function writeLang(l: Lang): void {
  cachedLang = l
  try {
    window.localStorage.setItem(STORAGE_KEY, l)
  } catch {
    /* ignore */
  }
  for (const cb of langSubs) cb()
}

// ---------- context ----------
interface I18nContextValue {
  lang: Lang
  dir: 'rtl' | 'ltr'
  setLang: (l: Lang) => void
  t: (key: DictKey, vars?: Record<string, string | number>) => string
  /** locale-aware number formatting (Persian digits for fa, latin for en) */
  num: (n: number, opts?: Intl.NumberFormatOptions) => string
  /** BCP-47 locale for toLocaleString/toLocaleTimeString */
  dateLocale: string
}

const I18nContext = createContext<I18nContextValue | null>(null)

const numberFormatters = new Map<string, Intl.NumberFormat>()

function formatterFor(locale: string, opts?: Intl.NumberFormatOptions): Intl.NumberFormat {
  const key = locale + JSON.stringify(opts ?? {})
  let f = numberFormatters.get(key)
  if (!f) {
    f = new Intl.NumberFormat(locale, opts)
    numberFormatters.set(key, f)
  }
  return f
}

export function I18nProvider({ children }: { children: ReactNode }) {
  // hydration-safe: server snapshot is 'fa' (matches <html lang="fa" dir="rtl">)
  const lang = useSyncExternalStore(subscribeLang, readLang, () => 'fa' as Lang)

  // keep <html> attributes in sync
  useEffect(() => {
    document.documentElement.lang = lang
    document.documentElement.dir = LANG_META[lang].dir
  }, [lang])

  const setLang = useCallback((l: Lang) => writeLang(l), [])

  const t = useCallback(
    (key: DictKey, vars?: Record<string, string | number>) =>
      interpolate(DICT[lang][key] ?? DICT.fa[key] ?? key, vars),
    [lang],
  )

  const num = useCallback(
    (n: number, opts?: Intl.NumberFormatOptions) => {
      const locale = lang === 'fa' ? 'fa-IR' : 'en-US'
      const safe = Number.isFinite(n) ? n : 0
      return formatterFor(locale, opts).format(safe)
    },
    [lang],
  )

  const value = useMemo<I18nContextValue>(
    () => ({
      lang,
      dir: LANG_META[lang].dir,
      setLang,
      t,
      num,
      dateLocale: lang === 'fa' ? 'fa-IR' : 'en-US',
    }),
    [lang, setLang, t, num],
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useI18n must be used inside <I18nProvider>')
  return ctx
}
