import type { SVGProps } from 'react'

type IconProps = SVGProps<SVGSVGElement>

function IconBase({ children, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      {children}
    </svg>
  )
}

export function ShieldIcon(props: IconProps) {
  return <IconBase {...props}><path d="M12 3 4.8 6v5.4c0 4.8 3 7.8 7.2 9.6 4.2-1.8 7.2-4.8 7.2-9.6V6L12 3Z" /><path d="m9.3 12 1.8 1.8 3.8-4" /></IconBase>
}

export function KeyIcon(props: IconProps) {
  return <IconBase {...props}><circle cx="8" cy="15" r="4" /><path d="m11 12 8-8m-2 2 2 2m-5 1 2 2" /></IconBase>
}

export function BellIcon(props: IconProps) {
  return <IconBase {...props}><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" /></IconBase>
}

export function LogOutIcon(props: IconProps) {
  return <IconBase {...props}><path d="M10 17l5-5-5-5m5 5H3m11-8h5a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-5" /></IconBase>
}

export function RefreshIcon(props: IconProps) {
  return <IconBase {...props}><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6.1 8a7 7 0 0 1 11.8-2L20 8M4 16l2.1 2a7 7 0 0 0 11.8-2" /></IconBase>
}

export function ChevronIcon(props: IconProps) {
  return <IconBase {...props}><path d="m9 18 6-6-6-6" /></IconBase>
}

export function ArrowLeftIcon(props: IconProps) {
  return <IconBase {...props}><path d="m15 18-6-6 6-6" /></IconBase>
}

export function ClockIcon(props: IconProps) {
  return <IconBase {...props}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></IconBase>
}

export function UserIcon(props: IconProps) {
  return <IconBase {...props}><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></IconBase>
}

export function CheckIcon(props: IconProps) {
  return <IconBase {...props}><path d="m5 12 4 4L19 6" /></IconBase>
}

export function InboxIcon(props: IconProps) {
  return <IconBase {...props}><path d="M4 4h16l2 11h-6l-2 3h-4l-2-3H2L4 4Z" /><path d="M8 9h8" /></IconBase>
}

export function CloseIcon(props: IconProps) {
  return <IconBase {...props}><path d="m6 6 12 12M18 6 6 18" /></IconBase>
}

export function WifiOffIcon(props: IconProps) {
  return <IconBase {...props}><path d="m2 2 20 20M8.5 8.5A9 9 0 0 1 21 9m-2.5 4.5a9 9 0 0 0-2.3-1.7M5 12.5A9 9 0 0 0 3 14m6 3a4 4 0 0 1 6 0m-3 4h.01" /></IconBase>
}
