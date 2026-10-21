import { useCallback, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { AccountContext } from '../lib/account'
import { ApiError, clearCsrf, get, message } from '../lib/api'
import type { Session, User } from '../lib/types'

export function AccountProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const generation = useRef(0)
  const signedOut = useCallback((notice = 'You have been signed out.') => {
    generation.current += 1
    clearCsrf()
    setUser(null)
    setSession(null)
    setError('')
    setNotice(notice)
    setLoading(false)
  }, [])
  const reload = useCallback(async () => {
    const current = ++generation.current
    setError('')
    try {
      const active = await get<Session>('/api/auth/session')
      const profile = await get<User>('/api/identity/users/me')
      if (current === generation.current) { setSession(active); setUser(profile); setNotice('') }
    } catch (caught) {
      if (current === generation.current) {
        if (caught instanceof ApiError && caught.status === 401) { setSession(null); setUser(null) }
        else setError(message(caught))
      }
      if (!(caught instanceof ApiError && caught.status === 401)) throw caught
    } finally { if (current === generation.current) setLoading(false) }
  }, [])
  useEffect(() => {
    const expired = () => signedOut('Your session has ended. Sign in again.')
    window.addEventListener('session-expired', expired)
    void reload().catch(() => {})
    return () => { generation.current += 1; window.removeEventListener('session-expired', expired) }
  }, [reload, signedOut])
  return <AccountContext value={{ user, session, loading, error, notice, reload, signedOut }}>{children}</AccountContext>
}
