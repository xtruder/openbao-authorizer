import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { runInNewContext } from 'node:vm'
import { describe, expect, it, vi } from 'vitest'

const workerSource = readFileSync(resolve(process.cwd(), 'public/push-sw.js'), 'utf8')

type WorkerEvent = {
  data?: { json: () => unknown }
  notification?: { close: () => void, data?: unknown }
  waitUntil: (operation: Promise<unknown>) => void
}
type WorkerHandler = (event: WorkerEvent) => void

type WindowClient = {
  navigate?: (url: string) => Promise<WindowClient>
  focus?: () => Promise<WindowClient>
}

function loadWorker(windowClients: WindowClient[] = []) {
  const handlers = new Map<string, WorkerHandler>()
  const showNotification = vi.fn(() => Promise.resolve())
  const matchAll = vi.fn(() => Promise.resolve(windowClients))
  const openWindow = vi.fn(() => Promise.resolve())
  const worker = {
    location: { origin: 'https://control.example' },
    registration: { showNotification },
    clients: { matchAll, openWindow },
    addEventListener: (type: string, handler: WorkerHandler) => handlers.set(type, handler),
  }
  runInNewContext(workerSource, { self: worker, URL })
  return { handlers, showNotification, matchAll, openWindow }
}

async function dispatch(handler: WorkerHandler, event: Omit<WorkerEvent, 'waitUntil'>) {
  let pending: Promise<unknown> | undefined
  handler({
    ...event,
    waitUntil(operation) {
      pending = Promise.resolve(operation)
    },
  })
  expect(pending).toBeDefined()
  await pending
}

describe('push service worker', () => {
  it('parses the generic notification envelope without rendering request fields', async () => {
    const { handlers, showNotification } = loadWorker()
    const push = handlers.get('push')
    expect(push).toBeDefined()

    await dispatch(push!, {
      data: {
        json: () => ({
          title: 'OpenBao approval pending',
          body: 'A new control-group request needs review.',
          url: '/requests?status=pending',
          path: 'secret/data/payroll',
          entity: 'Alice',
          accessor: 'must-not-leak',
        }),
      },
    })

    expect(showNotification).toHaveBeenCalledWith('OpenBao approval pending', expect.objectContaining({
      body: 'A new control-group request needs review.',
      data: { url: '/requests?status=pending' },
    }))
    const renderedNotification = JSON.stringify(showNotification.mock.calls[0])
    expect(renderedNotification).not.toContain('secret/data/payroll')
    expect(renderedNotification).not.toContain('Alice')
    expect(renderedNotification).not.toContain('must-not-leak')
  })

  it('uses generic defaults when payload JSON is malformed and rejects cross-origin targets', async () => {
    const malformedWorker = loadWorker()
    await dispatch(malformedWorker.handlers.get('push')!, {
      data: { json: () => { throw new SyntaxError('invalid JSON') } },
    })
    expect(malformedWorker.showNotification).toHaveBeenCalledWith('OpenBao approval pending', expect.objectContaining({
      body: 'A new control-group request needs review.',
      data: { url: '/' },
    }))

    const crossOriginWorker = loadWorker()
    await dispatch(crossOriginWorker.handlers.get('push')!, {
      data: {
        json: () => ({
          title: 'OpenBao approval pending',
          body: 'A new control-group request needs review.',
          url: 'https://attacker.example/approval',
        }),
      },
    })
    expect(crossOriginWorker.showNotification).toHaveBeenCalledWith('OpenBao approval pending', expect.objectContaining({
      data: { url: '/' },
    }))
  })

  it('navigates and focuses an existing window using only a same-origin target', async () => {
    const client: WindowClient = {
      navigate: vi.fn(() => Promise.resolve(client)),
      focus: vi.fn(() => Promise.resolve(client)),
    }
    const { handlers, matchAll } = loadWorker([client])
    const close = vi.fn()

    await dispatch(handlers.get('notificationclick')!, {
      notification: { close, data: { url: '/requests?status=pending#inbox' } },
    })

    expect(close).toHaveBeenCalledOnce()
    expect(matchAll).toHaveBeenCalledWith({ type: 'window', includeUncontrolled: true })
    expect(client.navigate).toHaveBeenCalledWith('https://control.example/requests?status=pending#inbox')
    expect(client.focus).toHaveBeenCalledOnce()
  })

  it('opens the application root instead of a cross-origin notification target', async () => {
    const { handlers, openWindow } = loadWorker()

    await dispatch(handlers.get('notificationclick')!, {
      notification: {
        close: vi.fn(),
        data: { url: 'https://attacker.example/approval' },
      },
    })

    expect(openWindow).toHaveBeenCalledWith('https://control.example/')
  })
})
