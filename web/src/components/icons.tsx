import type { SVGProps } from 'react'
import type { AssetKind } from '@/types/api'

type IconProps = SVGProps<SVGSVGElement>

function Icon({ children, ...props }: IconProps) {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      {children}
    </svg>
  )
}

/**
 * The NETY mark: three nodes wired into one graph, laid across a dashed
 * segment boundary. Two nodes sit on one side, one on the other, and the
 * links run straight through the boundary - which is the whole job of the
 * tool: map the nodes, then find out whether the boundary actually holds.
 *
 * Drawn on a 24-unit grid with heavy strokes so it survives 16px favicons and
 * the 24px header. The nodes and links take the accent token; the boundary
 * takes currentColor so it stays readable on a light or a dark surface.
 */
export function NetyMark({ size = 24, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className={className}
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M12.5 2v20"
        stroke="currentColor"
        strokeOpacity="0.4"
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray="2 3"
      />
      <path
        d="M5 7v10M5 7l14 5M5 17l14-5"
        stroke="rgb(var(--c-accent))"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="5" cy="7" r="2.9" fill="rgb(var(--c-accent))" />
      <circle cx="5" cy="17" r="2.9" fill="rgb(var(--c-accent))" />
      <circle cx="19" cy="12" r="2.9" fill="rgb(var(--c-accent))" />
    </svg>
  )
}

export const XIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M18 6 6 18M6 6l12 12" />
  </Icon>
)

export const SearchIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.5-3.5" />
  </Icon>
)

export const PlusIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 5v14M5 12h14" />
  </Icon>
)

export const PlayIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M7 4.5 19 12 7 19.5z" fill="currentColor" stroke="none" />
  </Icon>
)

export const PauseIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M8 5v14M16 5v14" strokeWidth="2.6" />
  </Icon>
)

export const StopIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="6" y="6" width="12" height="12" rx="1.5" fill="currentColor" stroke="none" />
  </Icon>
)

export const RefreshIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M20 11a8 8 0 1 0-.6 4" />
    <path d="M20 4v7h-7" />
  </Icon>
)

export const DownloadIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 3v12M7 11l5 5 5-5" />
    <path d="M5 20h14" />
  </Icon>
)

export const ChevronRightIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="m9 5 7 7-7 7" />
  </Icon>
)

export const ChevronDownIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="m5 9 7 7 7-7" />
  </Icon>
)

export const ChevronUpIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="m5 15 7-7 7 7" />
  </Icon>
)

export const TrashIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 7h16M10 11v6M14 11v6" />
    <path d="M6 7l1 13h10l1-13M9 7V4h6v3" />
  </Icon>
)

export const EditIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z" />
  </Icon>
)

export const MergeIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 3v6a5 5 0 0 0 5 5h7" />
    <path d="M18 3v6a5 5 0 0 1-5 5" />
    <path d="m15 11 3 3-3 3" />
  </Icon>
)

export const AlertIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 4 2.5 20h19z" />
    <path d="M12 10v4M12 17.2v.1" />
  </Icon>
)

export const CheckIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="m4 12 5 5L20 6" />
  </Icon>
)

export const CopyIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M5 15V5a2 2 0 0 1 2-2h8" />
  </Icon>
)

export const SunIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4" />
  </Icon>
)

export const MoonIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z" />
  </Icon>
)

export const LogoutIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4" />
    <path d="M10 8 6 12l4 4M6 12h11" />
  </Icon>
)

export const LockIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="4" y="10" width="16" height="10" rx="2" />
    <path d="M8 10V7a4 4 0 0 1 8 0v3" />
  </Icon>
)

// --- navigation ------------------------------------------------------------

export const OverviewIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="3" width="7" height="8" rx="1.5" />
    <rect x="14" y="3" width="7" height="5" rx="1.5" />
    <rect x="3" y="15" width="7" height="6" rx="1.5" />
    <rect x="14" y="11" width="7" height="10" rx="1.5" />
  </Icon>
)

export const NetworkIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="15" width="6" height="5" rx="1.2" />
    <rect x="15" y="15" width="6" height="5" rx="1.2" />
    <rect x="9" y="3" width="6" height="5" rx="1.2" />
    <path d="M12 8v4M6 15v-3h12v3" />
  </Icon>
)

export const ScanIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 8V5.5A1.5 1.5 0 0 1 5.5 4H8M16 4h2.5A1.5 1.5 0 0 1 20 5.5V8M20 16v2.5a1.5 1.5 0 0 1-1.5 1.5H16M8 20H5.5A1.5 1.5 0 0 1 4 18.5V16" />
    <path d="M4 12h16" />
  </Icon>
)

export const HostIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="4" width="18" height="7" rx="1.5" />
    <rect x="3" y="13" width="18" height="7" rx="1.5" />
    <path d="M7 7.5v.1M7 16.5v.1" />
  </Icon>
)

export const ServiceIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 7h16M4 12h16M4 17h10" />
    <circle cx="18" cy="17" r="2.2" />
  </Icon>
)

export const FindingIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 3 4 6.5v5.2c0 4.5 3.2 8.5 8 9.3 4.8-.8 8-4.8 8-9.3V6.5z" />
    <path d="M12 9v4M12 16.2v.1" />
  </Icon>
)

export const AssetIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z" />
    <path d="m12 12 8-4.5M12 12v9M12 12 4 7.5" />
  </Icon>
)

export const MatrixIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <path d="M9 3v18M15 3v18M3 9h18M3 15h18" />
  </Icon>
)

export const ExportIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5" />
    <path d="M12 11v6M9.5 14.5 12 17l2.5-2.5" />
  </Icon>
)

export const UsersIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="9" cy="8" r="3.2" />
    <path d="M3.5 20a5.5 5.5 0 0 1 11 0" />
    <path d="M16 5.5a3 3 0 0 1 0 5.6M17.5 20a5.6 5.6 0 0 0-2-4.2" />
  </Icon>
)

export const AuditIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 3h9l4 4v14H6z" />
    <path d="M14 3v5h5M9 12h7M9 16h5" />
  </Icon>
)

export const ImportIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 15V3" />
    <path d="m7 8 5-5 5 5" />
    <path d="M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4" />
  </Icon>
)

export const SettingsIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="3" />
    <path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9 17 7M7 17l-2.1 2.1" />
  </Icon>
)

export const TrunkIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M3 7h18M3 12h18M3 17h18" />
    <path d="m16 4 4 3-4 3" />
  </Icon>
)

export const HelpIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M9.5 9.3a2.6 2.6 0 1 1 3.4 2.5c-.6.2-.9.7-.9 1.3v.4M12 16.8v.1" />
  </Icon>
)

export const BoltIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M13 2 4 14h7l-1 8 9-12h-7z" />
  </Icon>
)

export const InfoIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5M12 8v.1" />
  </Icon>
)

export const FilterIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M3 5h18l-7 8v6l-4 2v-8z" />
  </Icon>
)

// --- asset kinds -----------------------------------------------------------

const WorkstationIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="4" width="18" height="12" rx="2" />
    <path d="M9 20h6M12 16v4" />
  </Icon>
)

const ServerIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="4" y="3" width="16" height="7" rx="1.5" />
    <rect x="4" y="14" width="16" height="7" rx="1.5" />
    <path d="M8 6.5v.1M8 17.5v.1" />
  </Icon>
)

const DCIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 3 4 6v6c0 4.2 3.3 7.8 8 9 4.7-1.2 8-4.8 8-9V6z" />
    <path d="M9 12h6M12 9v6" />
  </Icon>
)

const RouterIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="12" width="18" height="8" rx="2" />
    <path d="M7 16.5v.1M11 16.5v.1M12 12V8M9 8a3 3 0 0 1 6 0" />
  </Icon>
)

const PrinterIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M7 9V3h10v6" />
    <rect x="3" y="9" width="18" height="7" rx="2" />
    <path d="M7 14h10v7H7z" />
  </Icon>
)

const IoTIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="7" y="7" width="10" height="10" rx="2" />
    <path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4" />
  </Icon>
)

const PhoneIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="6" y="2" width="12" height="20" rx="2.5" />
    <path d="M10 18h4" />
  </Icon>
)

const HypervisorIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="m12 3 9 4.5-9 4.5-9-4.5z" />
    <path d="m3 12 9 4.5 9-4.5M3 16.5 12 21l9-4.5" />
  </Icon>
)

const StorageIcon = (p: IconProps) => (
  <Icon {...p}>
    <ellipse cx="12" cy="6" rx="8" ry="3" />
    <path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6" />
    <path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
  </Icon>
)

const UnknownIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M9.5 9.5a2.5 2.5 0 1 1 3.3 2.4c-.5.2-.8.7-.8 1.2v.4M12 16.5v.1" />
  </Icon>
)

const ASSET_ICONS: Record<AssetKind, (p: IconProps) => JSX.Element> = {
  unknown: UnknownIcon,
  workstation: WorkstationIcon,
  server: ServerIcon,
  'domain-controller': DCIcon,
  'network-device': RouterIcon,
  printer: PrinterIcon,
  iot: IoTIcon,
  voip: PhoneIcon,
  hypervisor: HypervisorIcon,
  storage: StorageIcon,
}

export function AssetKindIcon({ kind, ...props }: IconProps & { kind: AssetKind }) {
  const Cmp = ASSET_ICONS[kind] ?? UnknownIcon
  return <Cmp {...props} />
}

export const ASSET_KIND_LABELS: Record<AssetKind, string> = {
  unknown: 'Unknown',
  workstation: 'Workstation',
  server: 'Server',
  'domain-controller': 'Domain controller',
  'network-device': 'Network device',
  printer: 'Printer',
  iot: 'IoT',
  voip: 'VoIP phone',
  hypervisor: 'Hypervisor',
  storage: 'Storage',
}
// Triage status icons. Small and flat, so they read at 13px beside a label.

export const TodoIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="8" />
  </Icon>
)

export const SpinnerIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="8" />
    <path d="M12 12V7" />
    <path d="M12 12l3.5 2" />
  </Icon>
)

export const FlagIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M5 21V4" />
    <path d="M5 4h11l-2 3.5L16 11H5" />
  </Icon>
)

export const SkipIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="8" />
    <path d="M9 12h6" />
  </Icon>
)
