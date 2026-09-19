const FENNEC_PUSH_ERROR =
  'This Android Firefox build could not connect to its push provider. Fennec requires a configured UnifiedPush distributor (for example Sunup) and “Use UnifiedPush” enabled in Fennec settings. Restart Fennec, then retry.'

export function pushEnrollmentErrorMessage(error: unknown, userAgent: string) {
  const message = error instanceof Error ? error.message : ''
  const androidFirefox = /Android/i.test(userAgent) && /Firefox\//i.test(userAgent)
  const subscriptionRetrievalFailure =
    error instanceof DOMException && error.name === 'AbortError'
    || /(?:could not|error) retriev(?:e|ing) push subscription/i.test(message)

  if (androidFirefox && subscriptionRetrievalFailure) return FENNEC_PUSH_ERROR
  return message || 'Unable to enable notifications.'
}
