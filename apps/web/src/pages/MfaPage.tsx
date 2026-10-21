import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { EmailOtpForm } from '../components/EmailOtpForm'
import { Card, Notice } from '../components/ui'
import { useAccount } from '../lib/account'
import { get, message, mutate } from '../lib/api'
import { useMfa } from '../lib/mfa'
import { passkey, passkeySupported } from '../lib/passkeys'
import type { Challenge } from '../lib/types'
import { useAction } from '../lib/use-action'

export function MfaPage() {
  const account = useAccount()
  const mfa = useMfa()
  const action = useAction()
  const [challenge, setChallenge] = useState<Challenge | null>(null)
  const [starting, setStarting] = useState(true)
  const [startupError, setStartupError] = useState('')
  const [now, setNow] = useState(Date.now())
  const creation = useRef<{ id: number; request: Promise<Challenge> } | null>(null)
  const pendingId = mfa.pending?.id
  const emailVerified = !!account.user?.verified_at
  const pending = challenge?.status === 'pending' && Date.parse(challenge.expires_at) > now

  useEffect(() => {
    if (!pendingId || !emailVerified) { setStarting(false); return }
    let active = true
    setStarting(true)
    setStartupError('')
    // StrictMode runs effects twice; share one creation request for this action.
    if (creation.current?.id !== pendingId) creation.current = { id: pendingId, request: mutate<Challenge>('/api/identity/challenges/email-otp') }
    void creation.current.request.then((created) => {
      if (active) { setChallenge(created); setNow(Date.now()) }
    }).catch((error) => { if (active) setStartupError(message(error)) })
      .finally(() => { if (active) setStarting(false) })
    return () => { active = false }
  }, [pendingId, emailVerified])

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  if (!mfa.pending) return <div className="auth-page"><h1>Security check.</h1>
    <Card title="No change is waiting"><p>Return to settings and submit the change you want to make.</p><Link to="/settings">Back to settings</Link></Card>
  </div>

  async function verify(code: string) {
    if (!challenge || !pending) throw new Error('Request a new code first.')
    try {
      setChallenge(await mutate<Challenge>(`/api/identity/challenges/${challenge.challenge_id}/verify`, { method: 'email_otp', code }))
    } catch (error) {
      const current = await get<Challenge>(`/api/identity/challenges/${challenge.challenge_id}`).catch(() => null)
      if (current) setChallenge(current)
      throw error
    }
    await mfa.complete()
  }

  return <div className="auth-page"><p className="eyebrow">ACCOUNT SECURITY</p><h1>Verify it’s you.</h1>
    <Card title={mfa.pending.title} description="Confirm your identity to finish this change.">
      <Notice error={startupError || action.error} success={action.success} />
      {emailVerified ? <>
        <p className="muted">{starting ? 'Sending a verification code…' : `Enter the code sent to ${account.user!.email}.`}</p>
        {challenge?.status === 'pending' && !pending && <p role="status">This code has expired. Please resend.</p>}
        {challenge?.status === 'exhausted' && <p role="status">Too many attempts. Please request another code.</p>}
        <EmailOtpForm key={challenge?.challenge_id || 'email-otp'} busy={starting || action.busy} pending={!!pending}
          onVerify={(code) => { void action.run(() => verify(code)) }}
          onResend={() => { void action.run(async () => {
            setStartupError('')
            setChallenge(await mutate<Challenge>('/api/identity/challenges/email-otp'))
            setNow(Date.now())
          }, 'A new code was sent to your email.') }} />
      </> : <p className="notice">Verify your primary email using its email link before requesting security codes.</p>}
      {passkeySupported() && <button className="text-button" disabled={starting || action.busy} onClick={() => {
        void action.run(async () => { await passkey(false); await mfa.complete() })
      }}>Use a passkey instead</button>}
      <div className="actions"><button className="secondary" disabled={action.busy} onClick={mfa.cancel}>Cancel</button></div>
    </Card>
  </div>
}
