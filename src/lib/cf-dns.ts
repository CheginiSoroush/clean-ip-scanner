/**
 * Cloudflare DNS sync core (hunt v6.5) — extracted from /api/dns/push so the
 * manual push route AND the auto-push scheduler (src/instrumentation.ts)
 * share byte-identical create/keep/delete semantics, timeouts and error text.
 *
 * SYNC semantics: after syncDnsRecords the record set (type = recordType) of
 * `recordName` equals EXACTLY the pushed `ips` list:
 *   • missing  → created (POST /dns_records)
 *   • matching → kept untouched
 *   • extras   → deleted (DELETE /dns_records/{id})
 */

const CF_BASE = 'https://api.cloudflare.com/client/v4'
const CF_TIMEOUT_MS = 15_000

export interface DnsSyncResult {
  ok: boolean
  created: number
  kept: number
  removed: number
  errors: string[]
}

export interface DnsSyncInput {
  cfToken: string
  zoneId: string
  recordName: string
  recordType: 'A' | 'AAAA'
  ttl: number
  proxied: boolean
  ips: string[]
}

export interface DnsRecord {
  id: string
  type?: string
  name?: string
  content: string
}

interface CfEnvelope {
  success?: boolean
  result?: unknown
  errors?: Array<{ code?: number; message?: string }>
}

/**
 * Thrown by the low-level helpers on LIST-level failure (the route maps it to
 * 502 'cloudflare_unreachable' / 502 'cloudflare_error'; the scheduler treats
 * it as a failed push attempt). Per-record create/delete failures never throw
 * out of syncDnsRecords — they ride result.errors instead.
 */
export class CfDnsError extends Error {
  readonly kind: 'unreachable' | 'cloudflare_error'
  readonly errors: string[]

  constructor(kind: 'unreachable' | 'cloudflare_error', errors: string[] = ['cloudflare_error']) {
    super(kind === 'unreachable' ? 'cloudflare_unreachable' : errors.join(' | '))
    this.name = 'CfDnsError'
    this.kind = kind
    this.errors = errors
  }
}

function cfHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
}

async function readJsonSafe(res: Response): Promise<CfEnvelope | null> {
  try {
    return (await res.json()) as CfEnvelope
  } catch {
    return null
  }
}

function cfErrors(envelope: CfEnvelope | null): string[] {
  const errs = envelope?.errors
  if (Array.isArray(errs) && errs.length > 0) {
    return errs
      .map((e) => (e && typeof e.message === 'string' && e.message ? e.message : 'cloudflare_error'))
      .slice(0, 5)
  }
  return ['cloudflare_error']
}

/** GET /zones/{zone}/dns_records?type&name&per_page=100 → valid records (throws CfDnsError) */
export async function listDnsRecords(
  input: Pick<DnsSyncInput, 'cfToken' | 'zoneId' | 'recordName'>,
  type?: 'A' | 'AAAA',
): Promise<DnsRecord[]> {
  // same param order as the original route (type, name, per_page) when filtered
  const query = type ? `type=${type}&` : ''
  let res: Response
  try {
    res = await fetch(
      `${CF_BASE}/zones/${encodeURIComponent(input.zoneId)}/dns_records?${query}name=${encodeURIComponent(input.recordName)}&per_page=100`,
      {
        headers: cfHeaders(input.cfToken),
        cache: 'no-store',
        signal: AbortSignal.timeout(CF_TIMEOUT_MS),
      },
    )
  } catch {
    throw new CfDnsError('unreachable')
  }
  const json = await readJsonSafe(res)
  if (!res.ok || !json?.success || !Array.isArray(json.result)) {
    throw new CfDnsError('cloudflare_error', cfErrors(json))
  }
  const rows = json.result as Array<{ id?: unknown; type?: unknown; name?: unknown; content?: unknown }>
  const records: DnsRecord[] = []
  for (const r of rows) {
    if (r && typeof r.content === 'string' && typeof r.id === 'string') {
      records.push({
        id: r.id,
        type: typeof r.type === 'string' ? r.type : undefined,
        name: typeof r.name === 'string' ? r.name : undefined,
        content: r.content,
      })
    }
  }
  return records
}

/** POST /dns_records {type,name,content,ttl,proxied} (throws CfDnsError) */
export async function createDnsRecord(input: DnsSyncInput, content: string): Promise<void> {
  let res: Response
  try {
    res = await fetch(`${CF_BASE}/zones/${encodeURIComponent(input.zoneId)}/dns_records`, {
      method: 'POST',
      headers: cfHeaders(input.cfToken),
      cache: 'no-store',
      signal: AbortSignal.timeout(CF_TIMEOUT_MS),
      body: JSON.stringify({
        type: input.recordType,
        name: input.recordName,
        content,
        ttl: input.ttl,
        proxied: input.proxied,
      }),
    })
  } catch {
    throw new CfDnsError('unreachable')
  }
  const json = await readJsonSafe(res)
  if (!res.ok || !json?.success) {
    throw new CfDnsError('cloudflare_error', cfErrors(json))
  }
}

/** DELETE /dns_records/{id} (throws CfDnsError) */
export async function deleteDnsRecord(
  input: Pick<DnsSyncInput, 'cfToken' | 'zoneId'>,
  recordId: string,
): Promise<void> {
  let res: Response
  try {
    res = await fetch(
      `${CF_BASE}/zones/${encodeURIComponent(input.zoneId)}/dns_records/${encodeURIComponent(recordId)}`,
      {
        method: 'DELETE',
        headers: cfHeaders(input.cfToken),
        cache: 'no-store',
        signal: AbortSignal.timeout(CF_TIMEOUT_MS),
      },
    )
  } catch {
    throw new CfDnsError('unreachable')
  }
  const json = await readJsonSafe(res)
  if (!res.ok || !json?.success) {
    throw new CfDnsError('cloudflare_error', cfErrors(json))
  }
}

/** per-record failure → the exact error text the manual-push route always used */
function cfErrText(e: unknown): string {
  if (e instanceof CfDnsError) {
    return e.kind === 'unreachable' ? 'request_failed' : e.errors.join(' | ')
  }
  return 'request_failed'
}

/** SYNC the record set to exactly `input.ips` (create missing / keep matches / delete extras). */
export async function syncDnsRecords(input: DnsSyncInput): Promise<DnsSyncResult> {
  const errors: string[] = []
  let created = 0
  let kept = 0
  let removed = 0

  // ----- 1. existing records of THIS type for the exact name (CfDnsError propagates) -----
  const existing = await listDnsRecords(input, input.recordType)
  const existingByContent = new Map(existing.map((r) => [r.content, r.id]))

  // ----- 2. create missing / count kept -----
  for (const ip of input.ips) {
    if (existingByContent.has(ip)) {
      kept += 1
      continue
    }
    try {
      await createDnsRecord(input, ip)
      created += 1
    } catch (e) {
      errors.push(`${ip}: ${cfErrText(e)}`)
    }
  }

  // ----- 3. delete extras (end state = exactly the pushed set) -----
  const wanted = new Set(input.ips)
  for (const rec of existing) {
    if (wanted.has(rec.content)) continue
    try {
      await deleteDnsRecord(input, rec.id)
      removed += 1
    } catch (e) {
      errors.push(`${rec.content}: ${cfErrText(e)}`)
    }
  }

  return { ok: errors.length === 0, created, kept, removed, errors }
}
