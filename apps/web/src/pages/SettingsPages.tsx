import { useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router'
import { MfaPanel } from '../components/MfaPanel'
import { Card, Field, NewPassword, Notice } from '../components/ui'
import { date, newPassword } from '../lib/forms'
import { useAccount } from '../lib/account'
import { useMfa } from '../lib/mfa'
import { mutate } from '../lib/api'
import type { SecondaryEmail, Session, SessionEvent } from '../lib/types'
import { useAction } from '../lib/use-action'
import { useResource } from '../lib/use-resource'

export function SettingsLayout() {
  const { user } = useAccount()
  const location = useLocation()
  return <div className="settings-page"><p className="eyebrow">YOUR ACCOUNT</p><h1>Account settings.</h1>
    <p className="intro">Manage your details, sign-in methods and connected sessions.</p>
    <div className="settings-grid"><aside><div className="account-name"><strong>{user!.username}</strong><span>{user!.email}</span></div>
      <nav className="settings-nav" aria-label="Account settings">
        <NavLink to="/settings/profile">Profile</NavLink>
        <NavLink to="/settings/emails">Emails</NavLink>
        <NavLink to="/settings/security">Security</NavLink>
        <NavLink to="/settings/sessions">Sessions</NavLink>
        <NavLink to="/settings/access">My access</NavLink>
      </nav>
    </aside><div className="settings-content">
      <Notice error={typeof location.state?.error === 'string' ? location.state.error : ''}
        success={typeof location.state?.notice === 'string' ? location.state.notice : ''} />
      <Outlet />
    </div></div>
  </div>
}

export function ProfilePage() {
  const account = useAccount()
  const action = useAction()
  const user = account.user!
  return <>
    <Card title="Profile" description="Your username is shown with your account.">
      <Notice error={action.error} success={action.success} />
      <form key={user.updated_at} onSubmit={(event) => {
        event.preventDefault()
        const data = new FormData(event.currentTarget)
        void action.run(async () => { await mutate('/api/identity/users/me', { username: data.get('username') }, 'PATCH'); await account.reload() }, 'Profile updated.')
      }}><fieldset disabled={action.busy}>
        <Field label="Username" name="username" autoComplete="nickname" defaultValue={user.username} required maxLength={120} />
        <button type="submit">{action.busy ? 'Saving…' : 'Save profile'}</button>
      </fieldset></form>
    </Card>
    <Card title="Account details"><dl className="details">
      <dt>Primary email</dt><dd>{user.email} <span className={`badge ${user.verified_at ? 'verified' : ''}`}>{user.verified_at ? 'Verified' : 'Unverified'}</span></dd>
      <dt>Joined</dt><dd>{date(user.created_at)}</dd>
      <dt>Last updated</dt><dd>{date(user.updated_at)}</dd>
    </dl><Link to="/settings/emails">Manage email addresses →</Link></Card>
  </>
}

export function EmailsPage() {
  const account = useAccount()
  const mfa = useMfa()
  const emails = useResource<SecondaryEmail[]>('/api/identity/users/me/emails')
  const action = useAction()
  const navigate = useNavigate()
  const user = account.user!
  return <>
    <Card title="Primary email" description="Account recovery and email security codes go to this address.">
      <p><strong>{user.email}</strong> <span className={`badge ${user.verified_at ? 'verified' : ''}`}>{user.verified_at ? 'Verified' : 'Unverified'}</span></p>
      <Notice error={action.error} success={action.success} />
      <div className="actions">
        {!user.verified_at && <button className="secondary" disabled={action.busy} onClick={() => { void action.run(async () => { await mutate('/api/auth/email/verification/request', { email: user.email }) }, 'Verification requested. Check your inbox; allow a minute between requests.') }}>Send verification link</button>}
        <button className="secondary" disabled={action.busy} onClick={() => { void action.run(async () => { await account.reload(); await emails.reload() }) }}>Refresh email status</button>
      </div>
    </Card>
    <Card title="Other email addresses" description="Verify an address before making it primary. Changing your primary email signs you out on every device.">
      <Notice error={emails.error} />
      {emails.loading && <p role="status">Loading email addresses…</p>}
      {!emails.loading && emails.data?.length === 0 && <p className="muted">No other email addresses yet.</p>}
      <ul className="item-list">{emails.data?.map((email) => <li key={email.secondary_email_id}>
        <div><strong>{email.email}</strong> <span className={`badge ${email.is_verified ? 'verified' : ''}`}>{email.is_verified ? 'Verified' : 'Unverified'}</span></div>
        <div className="actions">
          {!email.is_verified && <button className="secondary" disabled={action.busy} onClick={() => { void action.run(async () => { await mutate(`/api/identity/users/me/emails/${email.secondary_email_id}/verification`) }, 'Verification requested. Check that address’s inbox.') }}>Send verification link</button>}
          {email.is_verified && <button className="secondary" disabled={action.busy} onClick={() => {
            if (!window.confirm(`Make ${email.email} your primary address? This signs you out everywhere.`)) return
            void action.run(() => mfa.run(async () => {
              await mutate(`/api/identity/users/me/emails/${email.secondary_email_id}/primary`)
              account.signedOut('Primary email changed. Sign in with your new email address.')
              void navigate('/login', { replace: true, state: { notice: 'Primary email changed. Sign in with your new email address.' } })
            }, { title: 'Change primary email', returnTo: '/settings/emails', success: '', signsOut: true }))
          }}>Make primary</button>}
          <button className="danger" disabled={action.busy} onClick={() => {
            if (!window.confirm(`Remove ${email.email} from your account?`)) return
            void action.run(() => mfa.run(async () => {
              await mutate(`/api/identity/users/me/emails/${email.secondary_email_id}`, undefined, 'DELETE')
              await emails.reload()
            }, { title: 'Remove email address', returnTo: '/settings/emails', success: 'Email address removed.' }), 'Email address removed.')
          }}>Remove</button>
        </div>
      </li>)}</ul>
      <form onSubmit={(event) => {
        event.preventDefault()
        const form = event.currentTarget
        const data = new FormData(form)
        const email = String(data.get('email'))
        void action.run(() => mfa.run(async () => {
          await mutate('/api/identity/users/me/emails', { email })
          form.reset()
          await emails.reload()
        }, { title: 'Add email address', returnTo: '/settings/emails', success: 'Email address added. Send its verification link next.' }), 'Email address added. Send its verification link next.')
      }}><fieldset disabled={action.busy}>
        <Field label="Add an email address" name="email" type="email" autoComplete="email" required maxLength={320} />
        <button type="submit">Add email address</button>
      </fieldset></form>
    </Card>
  </>
}

export function SecurityPage() {
  const account = useAccount()
  const mfa = useMfa()
  const navigate = useNavigate()
  const action = useAction()
  return <><MfaPanel /><Card title="Change password" description="We’ll ask you to verify your identity if needed. Changing your password signs you out on every device.">
    <Notice error={action.error} />
    <form onSubmit={(event) => {
      event.preventDefault()
      const form = event.currentTarget
      const data = new FormData(form)
      void action.run(async () => {
        const password = newPassword(data)
        await mfa.run(async () => {
          await mutate('/api/identity/auth/password/change', { new_password: password })
          form.reset()
          account.signedOut('Password changed. Sign in with your new password.')
          void navigate('/login', { replace: true, state: { notice: 'Password changed. Sign in with your new password.' } })
        }, { title: 'Change password', returnTo: '/settings/security', success: '', signsOut: true })
      })
    }}><fieldset disabled={action.busy}><NewPassword /><button type="submit">{action.busy ? 'Changing password…' : 'Change password'}</button></fieldset></form>
  </Card></>
}

function EventHistory({ sessionId }: { sessionId: string }) {
  const [offset, setOffset] = useState(0)
  const events = useResource<SessionEvent[]>(`/api/auth/sessions/${sessionId}/events?limit=20&offset=${offset}`)
  return <div className="inset"><h3>Session activity</h3><Notice error={events.error} />
    {events.loading && <p role="status">Loading activity…</p>}
    {!events.loading && events.data?.length === 0 && <p>No activity on this page.</p>}
    <ol className="events">{events.data?.map((event) => <li key={event.event_id}><strong>{event.event_type.replaceAll('_', ' ')}</strong> · {date(event.created_at)}{event.reason && <span> · {event.reason.replaceAll('_', ' ')}</span>}</li>)}</ol>
    <div className="actions"><button className="secondary" disabled={events.loading || offset === 0} onClick={() => setOffset(offset - 20)}>Previous events</button>
      <button className="secondary" disabled={events.loading || events.data?.length !== 20} onClick={() => setOffset(offset + 20)}>Next events</button></div>
  </div>
}

export function SessionsPage() {
  const account = useAccount()
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)
  const sessions = useResource<Session[]>(`/api/auth/sessions?limit=20&offset=${offset}`)
  const action = useAction()
  const navigate = useNavigate()
  function leave(notice: string) { account.signedOut(notice); void navigate('/login', { replace: true, state: { notice } }) }
  return <Card title="Sessions" description="Review where your account is signed in. Revoked and expired sessions remain visible while history is retained.">
    <Notice error={action.error || sessions.error} success={action.success} />
    <div className="actions"><button className="secondary" disabled={sessions.loading || action.busy} onClick={() => { void action.run(async () => { await sessions.reload() }) }}>Refresh sessions</button>
      <button className="danger" disabled={action.busy} onClick={() => {
        if (!window.confirm('Sign out of every session, including this one?')) return
        void action.run(async () => { await mutate('/api/auth/logout-all'); leave('You have been signed out on all devices.') })
      }}>Sign out everywhere</button></div>
    {sessions.loading && <p role="status">Loading sessions…</p>}
    {!sessions.loading && sessions.data?.length === 0 && <p>No sessions on this page.</p>}
    <ul className="item-list">{sessions.data?.map((session) => <li key={session.session_id}>
      <div className="session-heading"><h3>{session.is_current ? 'This browser' : 'Browser session'}</h3>
        <span className={`badge ${!session.revoked_at && Date.parse(session.expires_at) > Date.now() ? 'verified' : ''}`}>{session.revoked_at ? 'Revoked' : Date.parse(session.expires_at) <= Date.now() ? 'Expired' : 'Active'}</span></div>
      <p className="user-agent">{session.user_agent || 'Unknown browser'}</p>
      <dl className="details"><dt>IP address</dt><dd>{session.ip_address || 'Unknown'}</dd><dt>Created</dt><dd>{date(session.created_at)}</dd><dt>Last used</dt><dd>{date(session.last_used_at)}</dd><dt>Expires</dt><dd>{date(session.expires_at)}</dd>
        {session.revoked_at && <><dt>Revoked</dt><dd>{date(session.revoked_at)} · {session.revoke_reason?.replaceAll('_', ' ')}</dd></>}</dl>
      <div className="actions"><button className="secondary" aria-expanded={selected === session.session_id} disabled={action.busy} onClick={() => setSelected(selected === session.session_id ? null : session.session_id)}>View activity</button>
        {!session.revoked_at && <button className="danger" disabled={action.busy} onClick={() => {
          if (!window.confirm(session.is_current ? 'Sign out of this browser?' : 'Revoke this session?')) return
          void action.run(async () => {
            await mutate(`/api/auth/sessions/${session.session_id}`, undefined, 'DELETE')
            if (session.is_current) leave('This browser has been signed out.')
            else await sessions.reload()
          }, 'Session revoked.')
        }}>{session.is_current ? 'Sign out this browser' : 'Revoke session'}</button>}</div>
      {selected === session.session_id && <EventHistory key={session.session_id} sessionId={session.session_id} />}
    </li>)}</ul>
    <div className="actions"><button className="secondary" disabled={action.busy || sessions.loading || offset === 0} onClick={() => { setSelected(null); setOffset(offset - 20) }}>Previous sessions</button>
      <button className="secondary" disabled={action.busy || sessions.loading || sessions.data?.length !== 20} onClick={() => { setSelected(null); setOffset(offset + 20) }}>Next sessions</button></div>
  </Card>
}

export function PermissionsPage() {
  const permissions = useResource<string[]>('/api/identity/users/me/permissions')
  return <Card title="My access" description="These permissions apply to Identity. Each application manages its own access rules.">
    <Notice error={permissions.error} />
    {permissions.loading && <p role="status">Loading permissions…</p>}
    {!permissions.loading && permissions.data?.length === 0 && <p>No additional Identity permissions have been assigned to your account.</p>}
    <ul className="permission-list">{permissions.data?.map((permission) => <li key={permission}><code>{permission}</code></li>)}</ul>
    <button className="secondary" disabled={permissions.loading} onClick={() => { void permissions.reload().catch(() => {}) }}>Refresh access</button>
  </Card>
}
