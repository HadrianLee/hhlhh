import { Field } from './ui'

export function EmailOtpForm({ busy, pending, onVerify, onResend }: {
  busy: boolean
  pending: boolean
  onVerify: (code: string) => void
  onResend: () => void
}) {
  return <form onSubmit={(event) => {
    event.preventDefault()
    if (pending && !busy) onVerify(String(new FormData(event.currentTarget).get('code')))
  }}><fieldset disabled={busy}>
    <Field label="Verification code" name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required minLength={6} maxLength={6} />
    <div className="actions">
      <button type="submit" disabled={!pending}>Verify code</button>
      <button type="button" className="secondary" onClick={onResend}>Resend code</button>
    </div>
  </fieldset></form>
}
