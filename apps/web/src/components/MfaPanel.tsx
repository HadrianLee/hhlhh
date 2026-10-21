import { useMfa } from '../lib/mfa'
import { passkey, passkeySupported } from '../lib/passkeys'
import { useAction } from '../lib/use-action'
import { Card, Notice } from './ui'

export function MfaPanel() {
  const mfa = useMfa()
  const action = useAction()
  const supported = passkeySupported()
  return <Card title="Passkeys" description="Use your device to confirm your identity for sensitive changes.">
    <Notice error={action.error} success={action.success} />
    <div className="actions">
      <button className="secondary" disabled={action.busy || !supported} onClick={() => {
        void action.run(() => passkey(false), 'Passkey verified. You can now make sensitive changes.')
      }}>Verify with passkey</button>
      <button className="secondary" disabled={action.busy || !supported} onClick={() => {
        void action.run(() => mfa.run(() => passkey(true), {
          title: 'Add passkey', returnTo: '/settings/security', success: 'Passkey enrolled.',
        }), 'Passkey enrolled.')
      }}>Add passkey</button>
    </div>
    {!supported && <p className="muted">Passkeys require a supported browser and a trusted HTTPS connection.</p>}
  </Card>
}
