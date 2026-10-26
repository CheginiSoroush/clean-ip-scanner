/**
 * CDN IP range presets for Clean IP Scanner — Web Edition.
 * Ranges are public, well-known published CIDR blocks.
 */

export interface CdnPreset {
  id: string;
  name: string;
  nameFa: string;
  description: string;
  /** tailwind-ish accent color token used by the UI */
  accent: string;
  /** approximate IP count string for display */
  scale: string;
  ranges: string[];
}

export const CDN_PRESETS: CdnPreset[] = [
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    nameFa: 'کلادفلر',
    description: 'محبوب‌ترین CDN دنیا — پیش‌فرض ابزار اصلی و بهترین گزینه برای فیلترشکن',
    accent: 'orange',
    scale: '۱.۵M+',
    ranges: [
      '103.21.244.0/22',
      '103.22.200.0/22',
      '103.31.4.0/22',
      '104.16.0.0/13',
      '104.24.0.0/14',
      '108.162.192.0/18',
      '131.0.72.0/22',
      '141.101.64.0/18',
      '162.158.0.0/15',
      '172.64.0.0/13',
      '173.245.48.0/20',
      '188.114.96.0/20',
      '190.93.240.0/20',
      '197.234.240.0/22',
      '198.41.128.0/17',
      '2400:cb00::/112',
      '2606:4700::/112',
      '2a06:98c0::/112',
    ],
  },
  {
    id: 'google',
    name: 'Google Cloud',
    nameFa: 'گوگل کلاد',
    description: 'رنج‌های گوگل شامل DNS عمومی و سرویس‌های ابری',
    accent: 'emerald',
    scale: '۳۰۰K+',
    ranges: [
      '8.8.4.0/24',
      '8.8.8.0/24',
      '64.233.160.0/19',
      '66.102.0.0/20',
      '72.14.192.0/18',
      '74.125.0.0/16',
      '142.250.0.0/15',
      '172.217.0.0/16',
      '216.58.192.0/19',
    ],
  },
  {
    id: 'fastly',
    name: 'Fastly',
    nameFa: 'فستلی',
    description: 'CDN محبوب سرویس‌های بزرگ مثل GitHub و Reddit',
    accent: 'rose',
    scale: '۱۵۰K+',
    ranges: [
      '23.235.32.0/20',
      '43.249.72.0/22',
      '103.244.50.0/24',
      '103.245.222.0/23',
      '103.245.224.0/24',
      '104.156.80.0/20',
      '140.248.64.0/18',
      '146.75.0.0/16',
      '151.101.0.0/16',
      '157.52.64.0/18',
      '167.82.0.0/17',
      '172.111.64.0/18',
      '185.31.16.0/22',
      '199.27.72.0/21',
      '199.232.0.0/16',
    ],
  },
  {
    id: 'cloudfront',
    name: 'CloudFront',
    nameFa: 'کلادفرانت (آمازون)',
    description: 'سرویس CDN آمازون AWS',
    accent: 'violet',
    scale: '۱M+',
    ranges: [
      '13.32.0.0/15',
      '13.224.0.0/12',
      '18.64.0.0/13',
      '18.160.0.0/12',
      '18.244.0.0/15',
      '52.84.0.0/15',
      '52.222.128.0/17',
      '54.230.0.0/16',
      '54.239.128.0/18',
      '64.252.64.0/18',
      '70.132.0.0/18',
      '99.84.0.0/16',
      '130.176.0.0/17',
      '204.246.168.0/22',
      '205.251.192.0/18',
      '216.137.32.0/19',
    ],
  },
  {
    id: 'azure',
    name: 'Azure CDN',
    nameFa: 'آژور (مایکروسافت)',
    description: 'رنج‌های CDN و سرویس‌های ابری مایکروسافت',
    accent: 'cyan',
    scale: '۳M+',
    ranges: [
      '13.64.0.0/11',
      '13.96.0.0/13',
      '13.104.0.0/14',
      '20.33.0.0/16',
      '20.36.0.0/14',
      '20.40.0.0/13',
      '20.48.0.0/12',
      '20.64.0.0/10',
      '20.112.0.0/13',
      '20.128.0.0/16',
      '20.184.0.0/13',
      '40.64.0.0/10',
    ],
  },
  {
    id: 'arvancloud',
    name: 'ArvanCloud',
    nameFa: 'آروان کلاد',
    description: 'CDN ایرانی — تأخیر بسیار پایین داخل ایران',
    accent: 'teal',
    scale: '۱K+',
    ranges: ['185.143.232.0/22', '185.51.200.0/22', '89.32.248.0/21'],
  },
  {
    id: 'gcore',
    name: 'Gcore',
    nameFa: 'جی‌کور',
    description: 'CDN جهانی با نقاط حضور (PoP) متعدد',
    accent: 'amber',
    scale: '۶۵K+',
    ranges: ['92.223.64.0/18', '5.101.80.0/22', '185.197.192.0/22'],
  },
];

export function getPreset(id: string): CdnPreset | undefined {
  return CDN_PRESETS.find((p) => p.id === id);
}

export function getPresetRanges(id: string): string[] {
  return getPreset(id)?.ranges ?? [];
}
