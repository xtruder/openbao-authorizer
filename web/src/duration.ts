import { create } from '@bufbuild/protobuf'
import { DurationSchema, type Duration } from '@bufbuild/protobuf/wkt'

const units = { h: 3600, m: 60, s: 1 } as const

// formatDuration renders whole seconds in the Go style approvers type back in, e.g. 1h30m.
export function formatDuration(duration: Duration | undefined) {
  if (!duration) return ''
  let remaining = Number(duration.seconds)
  if (remaining <= 0) return '0s'
  return Object.entries(units).map(([unit, size]) => {
    const count = Math.floor(remaining / size)
    remaining -= count * size
    return count ? `${count}${unit}` : ''
  }).join('')
}

// parseDuration accepts Go-style h/m/s durations such as 30m or 1h30m.
export function parseDuration(value: string): Duration | undefined {
  const trimmed = value.trim()
  if (!/^(\d+[hms])+$/.test(trimmed)) return undefined
  let seconds = 0
  for (const [, count, unit] of trimmed.matchAll(/(\d+)([hms])/g)) {
    seconds += Number(count) * units[unit as keyof typeof units]
  }
  if (seconds <= 0 || !Number.isSafeInteger(seconds)) return undefined
  return create(DurationSchema, { seconds: BigInt(seconds) })
}
