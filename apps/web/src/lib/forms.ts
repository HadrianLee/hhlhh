export function newPassword(data: FormData): string {
  const password = String(data.get('password'))
  if (password !== data.get('confirm_password')) throw new Error('The passwords do not match.')
  if (Array.from(password).length < 8) throw new Error('Your password must contain at least 8 characters.')
  return password
}
export function date(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—'
}
