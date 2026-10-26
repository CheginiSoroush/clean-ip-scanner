import * as React from 'react'
import { cn } from '@/lib/utils'

/** Small keyboard-key chip. */
function Kbd({ className, ...props }: React.HTMLAttributes<HTMLElement>) {
  return (
    <kbd
      className={cn(
        'pointer-events-none inline-flex h-5 min-w-5 select-none items-center justify-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground',
        className,
      )}
      {...props}
    />
  )
}

export { Kbd }
