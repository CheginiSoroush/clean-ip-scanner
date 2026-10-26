/**
 * Xray/V2Ray outbound config generator for Clean IP Scanner — Web Edition.
 *
 * Clean IPs found by the scanner are meant to be used inside a proxy client
 * (Xray / V2Ray / v2rayNG / Nekobox / Hiddify…) where the raw CDN IP replaces
 * the resolved address while SNI/Host keeps pointing at the real domain.
 * These helpers build ready-to-paste outbounds + share links for the
 * three protocols that dominate CDN-fronted setups: VLESS, VMess, Trojan.
 */

import type { LiveResult } from '@/lib/scan-protocol'

export type XrayProtocol = 'vless' | 'vmess' | 'trojan'
export type XrayTransport = 'ws' | 'tcp'

/** sensible default SNI per preset — hosts that the CDN edge actually terminates TLS for */
export const PROBE_HOSTS: Record<string, string> = {
  cloudflare: 'speed.cloudflare.com',
  google: 'dns.google',
  fastly: 'fastly.com',
  cloudfront: 'd1v9xud5fukyx3.cloudfront.net',
  azure: 'azure.microsoft.com',
  arvancloud: 'arvancloud.ir',
  gcore: 'gcore.com',
}

export const DEFAULT_PROBE_HOST = 'speed.cloudflare.com'

export function probeHostFor(preset?: string): string {
  return (preset && PROBE_HOSTS[preset]) || DEFAULT_PROBE_HOST
}

/** stable fake UUID per IP so share links stay consistent between copies */
function uuidFromIp(ip: string): string {
  // FNV-1a-ish 4 rounds to fill 32 hex chars — deterministic, not cryptographic
  let h1 = 0x811c9dc5
  let h2 = 0x01000193
  let h3 = 0xdeadbeef
  let h4 = 0x1234567
  for (let i = 0; i < ip.length; i++) {
    const c = ip.charCodeAt(i)
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0
    h2 = Math.imul(h2 + c, 0x85ebca6b) >>> 0
    h3 = Math.imul(h3 ^ (c + i), 0xc2b2ae35) >>> 0
    h4 = Math.imul(h4 - c, 0x27d4eb2f) >>> 0
  }
  const hex = (n: number) => (n >>> 0).toString(16).padStart(8, '0')
  const raw = `${hex(h1)}${hex(h2)}${hex(h3)}${hex(h4)}`
  return `${raw.slice(0, 8)}-${raw.slice(8, 12)}-4${raw.slice(13, 16)}-a${raw.slice(17, 20)}-${raw.slice(20, 32)}`
}

export interface BuildConfigInput {
  ip: string
  port: number
  host: string
  protocol: XrayProtocol
  transport: XrayTransport
  /** ws path, default '/ws' (ignored for tcp) */
  path?: string
  /** remark/name inside the config */
  remark?: string
}

const cleanWsPath = (p?: string) => {
  const raw = (p ?? '').trim() || '/ws'
  return raw.startsWith('/') ? raw : `/${raw}`
}

/** build the outbound JSON for the requested protocol (Xray "outbounds[0]" shape) */
export function buildOutbound(input: BuildConfigInput): Record<string, unknown> {
  const { ip, port, host, protocol, transport } = input
  const path = cleanWsPath(input.path)
  const stream = {
    network: transport,
    security: 'tls',
    tlsSettings: {
      serverName: host,
      allowInsecure: false,
      alpn: ['h2', 'http/1.1'],
    },
    ...(transport === 'ws'
      ? { wsSettings: { path, headers: { Host: host } } }
      : { tcpSettings: { header: { type: 'none' } } }),
  }

  if (protocol === 'vless') {
    return {
      tag: `clean-${ip}`,
      protocol: 'vless',
      settings: {
        vnext: [
          {
            address: ip,
            port,
            users: [{ id: uuidFromIp(ip), encryption: 'none', flow: '' }],
          },
        ],
      },
      streamSettings: stream,
    }
  }
  if (protocol === 'vmess') {
    return {
      tag: `clean-${ip}`,
      protocol: 'vmess',
      settings: {
        vnext: [
          {
            address: ip,
            port,
            users: [
              { id: uuidFromIp(ip), alterId: 0, security: 'auto', level: 8 },
            ],
          },
        ],
      },
      streamSettings: stream,
    }
  }
  return {
    tag: `clean-${ip}`,
    protocol: 'trojan',
    settings: {
      servers: [{ address: ip, port, password: uuidFromIp(ip) }],
    },
    streamSettings: stream,
  }
}

/** full minimal Xray config (inbounds + outbounds) that can be dropped into config.json */
export function buildFullConfig(input: BuildConfigInput): string {
  return JSON.stringify(
    {
      log: { loglevel: 'warning' },
      inbounds: [
        {
          tag: 'socks',
          port: 10808,
          listen: '127.0.0.1',
          protocol: 'socks',
          settings: { udp: true },
        },
        {
          tag: 'http',
          port: 10809,
          listen: '127.0.0.1',
          protocol: 'http',
        },
      ],
      outbounds: [buildOutbound(input), { tag: 'direct', protocol: 'freedom' }],
      routing: {
        domainStrategy: 'AsIs',
        rules: [{ type: 'field', outboundTag: 'direct', ip: ['geoip:private'] }],
      },
    },
    null,
    2,
  )
}

/** standard URI share link (works in v2rayNG / Nekobox / Hiddify…) */
export function buildShareLink(input: BuildConfigInput): string {
  const { ip, port, host, protocol, transport } = input
  const path = cleanWsPath(input.path)
  const remark = encodeURIComponent(input.remark ?? `Clean ${ip}`)
  const id = uuidFromIp(ip)
  const params = new URLSearchParams({
    security: 'tls',
    sni: host,
    host,
    type: transport,
    ...(transport === 'ws' ? { path } : {}),
    alpn: 'h2,http/1.1',
  })
  if (protocol === 'vmess') {
    // vmess links are base64 JSON
    const payload = {
      v: '2',
      ps: input.remark ?? `Clean ${ip}`,
      add: ip,
      port: String(port),
      id,
      aid: '0',
      scy: 'auto',
      net: transport,
      type: 'none',
      host,
      path: transport === 'ws' ? path : '',
      tls: 'tls',
      sni: host,
      alpn: 'h2,http/1.1',
    }
    return `vmess://${btoa(JSON.stringify(payload))}`
  }
  if (protocol === 'trojan') {
    return `trojan://${id}@${ip}:${port}?${params.toString()}#${remark}`
  }
  return `vless://${id}@${ip}:${port}?${params.toString()}#${remark}`
}

/** one-line summary used in dialog headers */
export function summarizeResult(r: LiveResult): string {
  const parts = [`${r.latencyMs.toFixed(1)} ms`]
  if ((r.totalSpeed ?? 0) > 0) parts.push(`${((r.totalSpeed ?? 0) / 1048576).toFixed(1)} MB/s`)
  return parts.join(' · ')
}
