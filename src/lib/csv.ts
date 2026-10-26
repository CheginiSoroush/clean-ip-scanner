/**
 * v7.5 — shared CSV export helpers (ONE blob-download implementation for every
 * history/journal exporter). Excel-safe conventions shared by all callers:
 *  - files start with a UTF-8 BOM (\uFEFF) so Excel detects UTF-8
 *  - optional fields render as EMPTY cells (never 0/"false") via csvNum/csvBool
 *  - values must contain no commas/quotes — callers join multi-value fields
 *    with ';' instead (hosts, CIDRs and endpoint strings never contain commas)
 */

import type { HuntScheduleJournalEntry } from './scan-protocol'

/** YYYYMMDD-HHmm file stamp in LOCAL time (matches the v7.2 journal CSV convention) */
export function csvFileStamp(d = new Date()): string {
  const p2 = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}-${p2(d.getHours())}${p2(d.getMinutes())}`
}

/** optional-number cell: '' for undefined/null/NaN, else String(n) */
export function csvNum(n: number | undefined | null): string {
  return typeof n === 'number' && Number.isFinite(n) ? String(n) : ''
}

/** optional-boolean cell: '' for undefined, else 'true'/'false' */
export function csvBool(b: boolean | undefined): string {
  return typeof b === 'boolean' ? String(b) : ''
}

/** build a BOM-prefixed CSV blob and trigger a client-side file download */
export function downloadCsv(filename: string, rows: string[]): void {
  const blob = new Blob(['\uFEFF' + rows.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// ---------- v7.6 — scheduler-journal CSV (ONE row-builder for the manual exporter AND the Telegram auto-attach) ----------

/**
 * v7.6 — journal CSV header. v7.2 shipped 7 columns; v7.6 appends the 8
 * per-fire settings-echo columns (empty cells for done/postponed events and
 * legacy fire entries recorded before the echo existed).
 */
export const JOURNAL_CSV_HEADER =
  'at_iso,at_ms,kind,tested,healthy,stopped,duration_ms,provider,target,batch,concurrency,host,port,speed,verify'

/** defensive string cell: strips any comma/quote (CSV breakers) and trims */
function csvStr(s: string | undefined): string {
  return typeof s === 'string' ? s.replace(/[",]/g, '').trim() : ''
}

/**
 * v7.6 — build the full scheduler-journal CSV rows (header included). Shared by
 * google-hunt-panel's manual «Download CSV» button and integrations-panel's
 * auto-attach to scheduled-run Telegram digests, so both files always carry the
 * exact same shape. Settings columns read entry.settings (kind=fire only).
 */
export function buildSchedulerJournalCsvRows(journal: HuntScheduleJournalEntry[]): string[] {
  const rows: string[] = [JOURNAL_CSV_HEADER]
  for (const e of journal) {
    // v7.6 — echo exists only on fire entries; done/postponed/legacy → all-empty settings cells
    const s = e.kind === 'fire' ? e.settings : undefined
    rows.push(
      [
        new Date(e.at).toISOString(),
        String(e.at),
        e.kind,
        csvNum(e.tested),
        csvNum(e.healthy),
        csvBool(e.stopped),
        csvNum(e.durationMs),
        csvStr(s?.provider),
        csvNum(s?.target),
        csvNum(s?.batchSize),
        csvNum(s?.concurrency),
        csvStr(s?.host),
        csvNum(s?.port),
        csvStr(s?.speed),
        csvNum(s?.verify),
      ].join(','),
    )
  }
  return rows
}
