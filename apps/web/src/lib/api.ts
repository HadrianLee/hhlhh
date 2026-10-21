let csrfToken: string | null = null
let csrfRequest: Promise<string> | null = null

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function errorDetail(body: unknown): string {
  if (!body || typeof body !== 'object') return 'The request could not be completed.'
  const problem = body as { detail?: unknown; title?: unknown }
  if (typeof problem.detail === 'string') return problem.detail
  if (Array.isArray(problem.detail)) {
    return problem.detail.map((item: { msg?: string }) => item.msg || 'Invalid input').join('. ')
  }
  return typeof problem.title === 'string' ? problem.title : 'The request could not be completed.'
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  if (!path.startsWith('/api/') || path.includes('\\')) throw new Error('Invalid API path')
  const response = await fetch(path, {
    ...init, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: { Accept: 'application/json', ...init.headers },
  })
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) csrfToken = null
    if (response.status === 401 && (path.startsWith('/api/identity/') || path.startsWith('/api/auth/session'))) {
      window.dispatchEvent(new Event('session-expired'))
    }
    const body: unknown = await response.json().catch(() => null)
    const detail = errorDetail(body)
    throw new ApiError(response.status, response.status === 429
      ? `${detail} Please wait ${response.headers.get('Retry-After') || '60'} seconds before trying again.` : detail)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function clearCsrf(): void { csrfToken = null }

export async function getCsrf(): Promise<string> {
  if (csrfToken) return csrfToken
  if (!csrfRequest) {
    csrfRequest = request<{ csrf_token: string }>('/api/auth/csrf')
      .then((body) => { csrfToken = body.csrf_token; return body.csrf_token })
      .finally(() => { csrfRequest = null })
  }
  return csrfRequest
}

export function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>(path, { signal })
}

export async function mutate<T = void>(path: string, body?: unknown, method = 'POST'): Promise<T> {
  const token = await getCsrf()
  const result = await request<T>(path, {
    method,
    headers: { 'X-CSRF-Token': token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (path === '/api/auth/login' || path === '/api/auth/passkey/login') csrfToken = (result as { csrf_token: string }).csrf_token
  if (path === '/api/auth/logout' || path === '/api/auth/logout-all'
      || path === '/api/identity/auth/password/change' || path.endsWith('/primary')) clearCsrf()
  return result
}

export function message(error: unknown): string {
  if (error instanceof TypeError) return 'Unable to reach the server. Check your connection and try again.'
  return error instanceof Error ? error.message : 'Something went wrong. Please try again.'
}
