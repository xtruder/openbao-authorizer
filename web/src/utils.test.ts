import { create } from '@bufbuild/protobuf'
import { DurationSchema } from '@bufbuild/protobuf/wkt'
import { describe, expect, it } from 'vitest'
import { formatDuration, parseDuration } from './utils'

describe('grant durations', () => {
  it('formats whole seconds like Go without zero units', () => {
    expect(formatDuration(create(DurationSchema, { seconds: 28800n }))).toBe('8h')
    expect(formatDuration(create(DurationSchema, { seconds: 5400n }))).toBe('1h30m')
    expect(formatDuration(create(DurationSchema, { seconds: 45n }))).toBe('45s')
    expect(formatDuration(undefined)).toBe('')
  })

  it('parses the h/m/s durations approvers type', () => {
    expect(parseDuration('30m')?.seconds).toBe(1800n)
    expect(parseDuration(' 1h30m ')?.seconds).toBe(5400n)
    expect(parseDuration('90s')?.seconds).toBe(90n)
  })

  it('rejects anything else', () => {
    for (const value of ['', 'soon', '1d', '1.5h', '-30m', '0s', '30']) {
      expect(parseDuration(value), value).toBeUndefined()
    }
  })
})
