import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router'
import { useAccount } from '../lib/account'
import { mutate } from '../lib/api'
import { captureLinkToken } from '../lib/link-token'
import type { LinkToken } from '../lib/link-token'
import { useAction } from '../lib/use-action'
import { Card, Field, NewPassword, Notice } from '../components/ui'
import { newPassword } from '../lib/forms'
import { passkeySupported, signInWithPasskey } from '../lib/passkeys'

export function LoginPage() {
  const account = useAccount()
  const action = useAction()
  const navigate = useNavigate()
  const location = useLocation()
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    void action.run(async () => {
      await mutate('/api/auth/login', { email: data.get('email'), password: data.get('password') })
      form.reset()
      await account.reload()
      void navigate('/settings', { replace: true })
    })
  }
  return <div className="auth-page"><p className="eyebrow">YOUR ACCOUNT</p><h1>Welcome back.</h1>
    <p className="intro">Sign in to manage your profile and account security.</p>
    <Card title="Sign in">
      <Notice error={action.error} success={typeof location.state?.notice === 'string' ? location.state.notice : ''} />
      <form onSubmit={submit}><fieldset disabled={action.busy}>
        <Field label="Email address" name="email" type="email" autoComplete="username" required maxLength={320} />
        <Field label="Password" name="password" type="password" autoComplete="current-password" required />
        <button type="submit">{action.busy ? 'Signing in…' : 'Sign in'}</button>
      </fieldset></form>
      <button className="secondary passkey-sign-in" type="button" disabled={action.busy || !passkeySupported()} onClick={() => {
        void action.run(async () => {
          await signInWithPasskey()
          await account.reload()
          void navigate('/settings', { replace: true })
        })
      }}>Sign in with passkey</button>
      {!passkeySupported() && <p className="muted">Passkey sign-in requires HTTPS and a supported browser.</p>}
      <div className="form-links"><Link to="/forgot-password">Forgot password?</Link><Link to="/register">Create an account</Link></div>
    </Card>
  </div>
}

export function RegisterPage() {
  const action = useAction()
  const navigate = useNavigate()
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    void action.run(async () => {
      await mutate('/api/auth/register', { email: data.get('email'), username: data.get('username'), password: newPassword(data) })
      form.reset()
      void navigate('/login', { state: { notice: 'Account created. Check your inbox for a verification link.' } })
    })
  }
  return <div className="auth-page"><p className="eyebrow">GET STARTED</p><h1>Create your account.</h1>
    <Card title="Your details" description="We’ll send a verification link to your email address.">
      <Notice error={action.error} />
      <form onSubmit={submit}><fieldset disabled={action.busy}>
        <Field label="Username" name="username" autoComplete="nickname" required maxLength={120} />
        <Field label="Email address" name="email" type="email" autoComplete="email" required maxLength={320} />
        <NewPassword />
        <button type="submit">{action.busy ? 'Creating account…' : 'Create account'}</button>
      </fieldset></form>
      <p className="form-links">Already registered? <Link to="/login">Sign in</Link></p>
    </Card>
  </div>
}

export function ForgotPasswordPage() {
  const action = useAction()
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    void action.run(async () => {
      await mutate('/api/auth/password/forgot', { email: data.get('email') })
    }, 'If this account exists, password reset instructions will be sent. Check your inbox.')
  }
  return <div className="auth-page"><p className="eyebrow">ACCOUNT RECOVERY</p><h1>Forgot your password?</h1>
    <Card title="Request a reset" description="Enter your primary email address to receive a reset link.">
      <Notice error={action.error} success={action.success} />
      <form onSubmit={submit}><fieldset disabled={action.busy}>
        <Field label="Email address" name="email" type="email" autoComplete="email" required maxLength={320} />
        <button type="submit">{action.busy ? 'Requesting…' : 'Send reset instructions'}</button>
      </fieldset></form>
      <div className="form-links"><Link to="/login">Back to sign in</Link></div>
    </Card>
  </div>
}

export function TokenPage({ purpose, initialToken }: { purpose: 'verify' | 'reset'; initialToken: LinkToken | null }) {
  const verifying = purpose === 'verify'
  const path = verifying ? '/verify-email' : '/reset-password'
  const [token, setToken] = useState(initialToken?.path === path ? initialToken.token : '')
  const [done, setDone] = useState(false)
  const action = useAction()
  const account = useAccount()
  useEffect(() => {
    function receiveLink() {
      const incoming = captureLinkToken(window.location, window.history)
      if (incoming?.path === path) { setToken(incoming.token); setDone(false) }
    }
    receiveLink()
    window.addEventListener('hashchange', receiveLink)
    window.addEventListener('popstate', receiveLink)
    return () => {
      window.removeEventListener('hashchange', receiveLink)
      window.removeEventListener('popstate', receiveLink)
    }
  }, [path])
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    void action.run(async () => {
      if (!token) throw new Error('Open the link from your email to continue.')
      if (verifying) await mutate('/api/auth/email/verification/confirm', { token })
      else await mutate('/api/auth/password/reset', { token, new_password: newPassword(data) })
      setToken('')
      form.reset()
      setDone(true)
      if (verifying) {
        if (account.user) await account.reload()
      } else account.signedOut()
    })
  }
  return <div className={`auth-page ${verifying ? 'verification-page' : ''}`}><p className="eyebrow">{verifying ? 'EMAIL VERIFICATION' : 'ACCOUNT RECOVERY'}</p>
    <h1>{verifying ? 'Verify your email.' : 'Choose a new password.'}</h1>
    <Card title={done ? (verifying ? 'Email verified' : 'Password updated') : (verifying ? 'Confirm your email address' : 'Reset password')}>
      {done ? <>
        <p role="status">{verifying ? 'Your email address is now verified.' : 'Your password has been reset. Sign in again on your devices.'}</p>
        <Link className="button" to={verifying && account.user ? '/settings/emails' : '/login'}>Continue</Link>
      </> : <>
        <p className="muted">{token
          ? (verifying ? 'Confirm your email address to finish verifying your account.' : 'Choose a new password to recover your account.')
          : 'Open the link from your email to continue.'}</p>
        <Notice error={action.error} />
        <form onSubmit={submit}><fieldset disabled={action.busy}>
          {!verifying && <NewPassword />}
          <button className={verifying ? 'verify-button' : undefined} type="submit" disabled={!token}>{action.busy ? 'Submitting…' : (verifying ? 'Verify' : 'Reset password')}</button>
        </fieldset></form>
      </>}
    </Card>
    <Link to={verifying && account.user ? '/settings/emails' : '/login'}>{verifying && account.user ? 'Back to email settings' : 'Back to sign in'}</Link>
  </div>
}
