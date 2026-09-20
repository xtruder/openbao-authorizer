import '@testing-library/jest-dom/vitest'
import { afterEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

class MockEventSource {
  static instances: MockEventSource[] = []
  readonly url: string
  onopen: ((event: Event) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  private listeners = new Map<string, EventListener[]>()

  constructor(url: string | URL) {
    this.url = String(url)
    MockEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: EventListener) {
    const existing = this.listeners.get(type) ?? []
    this.listeners.set(type, [...existing, listener])
  }

  removeEventListener(type: string, listener: EventListener) {
    const existing = this.listeners.get(type) ?? []
    this.listeners.set(type, existing.filter((candidate) => candidate !== listener))
  }

  close() {}
}

vi.stubGlobal('EventSource', MockEventSource)

afterEach(() => {
  cleanup()
  localStorage.clear()
  sessionStorage.clear()
  window.history.replaceState({}, '', '/')
  vi.restoreAllMocks()
  MockEventSource.instances = []
})
