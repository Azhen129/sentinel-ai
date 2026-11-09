/** A caller cancellation signal must not disable the network deadline. */
export async function requestJson<T>(url: string, options: RequestInit = {}, timeoutMs = 12000): Promise<T> {
  const deadline = new AbortController()
  const abortFromCaller = () => deadline.abort(options.signal?.reason)
  if (options.signal?.aborted) abortFromCaller()
  else options.signal?.addEventListener('abort', abortFromCaller, { once: true })
  const timer = setTimeout(() => deadline.abort(new DOMException('Request timed out. Retry when the backend is available.', 'TimeoutError')), timeoutMs)
  try {
    const headers = new Headers(options.headers)
    if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    const response = await fetch(url, { ...options, headers, signal: deadline.signal })
    if (!response.ok) {
      let message = `Request failed (${response.status})`
      try { const error = await response.json(); message = typeof error.detail === 'string' ? error.detail : message } catch { /* retain useful HTTP status */ }
      throw new Error(message)
    }
    return await response.json() as T
  } finally {
    clearTimeout(timer)
    options.signal?.removeEventListener('abort', abortFromCaller)
  }
}
