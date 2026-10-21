import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { useAccount } from '../lib/account'
import { ApiError, get, message } from '../lib/api'
import { MfaContext } from '../lib/mfa'
import type { MfaActionOptions, PendingMfaAction } from '../lib/mfa'
import type { MfaStatus } from '../lib/types'

function recent(status: MfaStatus): boolean {
  return !!status.verified_at && !!status.expires_at && Date.parse(status.expires_at) > Date.now()
}

export function MfaProvider({ children }: { children: ReactNode }) {
  const account = useAccount()
  const navigate = useNavigate()
  const location = useLocation()
  const [pending, setPending] = useState<PendingMfaAction | null>(null)
  const operation = useRef<{ info: PendingMfaAction; perform: () => Promise<void> } | null>(null)
  const counter = useRef(0)
  const busy = useRef(false)
  const session = account.user && account.session ? `${account.user.user_id}:${account.session.session_id}` : null
  const currentSession = useRef<string | null>(session)

  const clear = useCallback(() => { operation.current = null; setPending(null) }, [])

  useLayoutEffect(() => {
    currentSession.current = session
    if (operation.current && operation.current.info.session !== session) clear()
  }, [session, clear])

  useEffect(() => {
    if (location.pathname !== '/mfa') clear()
  }, [location.pathname, clear])

  function assertSession(expected: string | null): asserts expected is string {
    if (!expected || currentSession.current !== expected) throw new Error('Your session changed. Please submit the change again.')
  }

  async function run(perform: () => Promise<void>, options: MfaActionOptions) {
    if (busy.current || operation.current) throw new Error('Finish or cancel the current security check first.')
    const expected = currentSession.current
    assertSession(expected)
    busy.current = true
    try {
      let verified = recent(await get<MfaStatus>('/api/identity/challenges/mfa'))
      assertSession(expected)
      if (verified) {
        try { await perform(); return true }
        catch (error) {
          // Only an explicit MFA rejection can defer a failed write. Never replay
          // a timeout, network failure, or an unrelated permission rejection.
          if (!(error instanceof ApiError && error.status === 403
              && error.message === 'Complete a recent MFA challenge for this session')) throw error
          verified = recent(await get<MfaStatus>('/api/identity/challenges/mfa'))
          if (verified) throw error
        }
      }
      assertSession(expected)
      const info = { ...options, id: ++counter.current, session: expected }
      operation.current = { info, perform }
      setPending(info)
      void navigate('/mfa')
      return false
    } finally { busy.current = false }
  }

  async function complete() {
    if (busy.current) return
    const queued = operation.current
    if (!queued) throw new Error('This change is no longer pending. Please submit it again.')
    assertSession(queued.info.session)
    busy.current = true
    try {
      const verified = recent(await get<MfaStatus>('/api/identity/challenges/mfa'))
      assertSession(queued.info.session)
      if (operation.current !== queued) throw new Error('This change was cancelled.')
      if (!verified) throw new Error('Verification expired. Request another code.')
      // Consume before executing so this action cannot be submitted twice.
      operation.current = null
      try {
        await queued.perform()
        if (!queued.info.signsOut && currentSession.current === queued.info.session) {
          void navigate(queued.info.returnTo, { replace: true, state: { notice: queued.info.success } })
        }
      } catch (error) {
        if (currentSession.current === queued.info.session) {
          void navigate(queued.info.returnTo, { replace: true, state: { error: message(error) } })
        }
        throw error
      } finally { setPending(null) }
    } finally { busy.current = false }
  }

  function cancel() {
    const returnTo = operation.current?.info.returnTo || '/settings'
    clear()
    void navigate(returnTo, { replace: true })
  }

  return <MfaContext value={{ pending, run, complete, cancel }}>{children}</MfaContext>
}
