import { useId } from 'react'
import type { InputHTMLAttributes, ReactNode } from 'react'

export function Field({ label, hint, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  const id = useId()
  return <div className="field">
    <label htmlFor={id}>{label}</label>
    <input {...props} id={id} aria-describedby={hint ? `${id}-hint` : undefined} />
    {hint && <small id={`${id}-hint`}>{hint}</small>}
  </div>
}
export function Notice({ error, success }: { error?: string; success?: string }) {
  return <>
    {error && <p className="notice error" role="alert">{error}</p>}
    {success && <p className="notice success" role="status">{success}</p>}
  </>
}
export function Card({ title, children, description }: { title: string; children: ReactNode; description?: string }) {
  return <section className="card"><h2>{title}</h2>{description && <p className="muted">{description}</p>}{children}</section>
}
export function NewPassword() {
  return <>
    <Field label="New password" name="password" type="password" autoComplete="new-password" required minLength={8}
      hint="At least 8 characters." />
    <Field label="Confirm new password" name="confirm_password" type="password" autoComplete="new-password" required minLength={8} />
  </>
}
