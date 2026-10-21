import { Link, Navigate, NavLink, Outlet, Route, Routes } from 'react-router'
import { AccountProvider } from './components/AccountProvider'
import { MfaProvider } from './components/MfaProvider'
import { Notice } from './components/ui'
import { useAccount } from './lib/account'
import { mutate } from './lib/api'
import type { LinkToken } from './lib/link-token'
import { useAction } from './lib/use-action'
import { ForgotPasswordPage, LoginPage, RegisterPage, TokenPage } from './pages/AuthPages'
import { MfaPage } from './pages/MfaPage'
import { EmailsPage, PermissionsPage, ProfilePage, SecurityPage, SessionsPage, SettingsLayout } from './pages/SettingsPages'
import './App.css'

function Layout() {
  const account = useAccount()
  const action = useAction()
  return <>
    <a className="skip-link" href="#content">Skip to content</a>
    <header className="site-header"><Link className="brand" to="/">HHLHH<span>Account</span></Link>
      <nav aria-label="Main navigation">
        {account.user ? <><NavLink to="/settings">Settings</NavLink><button className="text-button" disabled={action.busy} onClick={() => {
          void action.run(async () => { await mutate('/api/auth/logout'); account.signedOut() })
        }}>{action.busy ? 'Signing out…' : 'Sign out'}</button></> : <><NavLink to="/login">Sign in</NavLink><NavLink to="/register">Create account</NavLink></>}
      </nav>
    </header>
    <main id="content"><Notice error={action.error} /><Outlet /></main>
    <footer className="site-footer">HHLHH · Account & security</footer>
  </>
}

function Protected() {
  const account = useAccount()
  if (account.loading) return <p className="loading" role="status">Loading your account…</p>
  if (account.error) return <div className="auth-page"><Notice error={account.error} /><button onClick={() => { void account.reload().catch(() => {}) }}>Try again</button></div>
  if (!account.user) return <Navigate to="/login" replace state={{ notice: account.notice || 'Sign in to manage your account.' }} />
  return <Outlet />
}

function Home() {
  const account = useAccount()
  if (account.loading) return <p className="loading" role="status">Loading…</p>
  return <Navigate to={account.user || account.error ? '/settings' : '/login'} replace />
}

function App({ initialToken }: { initialToken: LinkToken | null }) {
  return <AccountProvider><MfaProvider><Routes>
    <Route element={<Layout />}>
      <Route index element={<Home />} />
      <Route path="login" element={<LoginPage />} />
      <Route path="register" element={<RegisterPage />} />
      <Route path="forgot-password" element={<ForgotPasswordPage />} />
      <Route path="reset-password" element={<TokenPage key="reset" purpose="reset" initialToken={initialToken} />} />
      <Route path="verify-email" element={<TokenPage key="verify" purpose="verify" initialToken={initialToken} />} />
      <Route element={<Protected />}>
        <Route path="mfa" element={<MfaPage />} />
        <Route path="settings" element={<SettingsLayout />}>
        <Route index element={<Navigate to="profile" replace />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="emails" element={<EmailsPage />} />
        <Route path="security" element={<SecurityPage />} />
        <Route path="sessions" element={<SessionsPage />} />
        <Route path="access" element={<PermissionsPage />} />
      </Route></Route>
      <Route path="*" element={<div className="auth-page"><h1>Page not found.</h1><Link to="/">Return to your account</Link></div>} />
    </Route>
  </Routes></MfaProvider></AccountProvider>
}

export default App
