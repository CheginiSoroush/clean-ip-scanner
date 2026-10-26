'use client'

/**
 * PwaRegister — registers the offline-shell service worker.
 * Production only: in dev, a caching SW would serve stale chunks after HMR.
 */

import { useEffect } from 'react'

export function PwaRegister() {
  useEffect(() => {
    if (process.env.NODE_ENV !== 'production') return
    if (!('serviceWorker' in navigator)) return
    const register = () => {
      navigator.serviceWorker.register('/sw.js').catch(() => {
        /* offline shell is a progressive enhancement — never break the app */
      })
    }
    if (document.readyState === 'complete') {
      register()
      return
    }
    window.addEventListener('load', register)
    return () => window.removeEventListener('load', register)
  }, [])

  return null
}
