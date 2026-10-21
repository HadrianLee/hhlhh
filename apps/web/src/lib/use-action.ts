import { useRef, useState } from 'react'
import { message } from './api'

export function useAction() {
  const lock = useRef(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  async function run(action: () => Promise<void | boolean>, notice = '') {
    if (lock.current) return
    lock.current = true
    setBusy(true)
    setError('')
    setSuccess('')
    try { if (await action() !== false) setSuccess(notice) }
    catch (caught) { setError(message(caught)) }
    finally { lock.current = false; setBusy(false) }
  }
  return { busy, error, success, run }
}
