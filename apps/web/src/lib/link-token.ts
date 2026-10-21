export interface LinkToken { path: string; token: string }

export function captureLinkToken(location: Pick<Location, 'pathname' | 'search' | 'hash'>,
  history: Pick<History, 'state' | 'replaceState'>): LinkToken | null {
  if (!['/verify-email', '/reset-password'].includes(location.pathname) || !location.hash) return null
  const token = new URLSearchParams(location.hash.slice(1)).get('token')
  // Remove the fragment before mounting React; tokens stay out of storage and query strings.
  history.replaceState(history.state, '', location.pathname + location.search)
  return token && token.length <= 512 ? { path: location.pathname, token } : null
}
