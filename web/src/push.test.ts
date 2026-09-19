import { describe, expect, it } from 'vitest'
import { pushEnrollmentErrorMessage } from './push'

describe('push enrollment diagnostics', () => {
  it('explains the Fennec UnifiedPush transport failure', () => {
    const error = new DOMException('Error retrieving push subscription.', 'AbortError')

    expect(pushEnrollmentErrorMessage(error, 'Mozilla/5.0 (Android 15; Mobile; rv:151.0) Gecko/151.0 Firefox/151.0')).toBe(
      'This Android Firefox build could not connect to its push provider. Fennec requires a configured UnifiedPush distributor (for example Sunup) and “Use UnifiedPush” enabled in Fennec settings. Restart Fennec, then retry.',
    )
  })

  it('preserves unrelated browser errors', () => {
    expect(pushEnrollmentErrorMessage(new Error('Network unavailable'), 'Firefox')).toBe('Network unavailable')
  })

  it('uses a safe fallback for non-errors', () => {
    expect(pushEnrollmentErrorMessage(null, 'Firefox')).toBe('Unable to enable notifications.')
  })
})
