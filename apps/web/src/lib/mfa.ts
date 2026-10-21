import { createContext, useContext } from 'react'

export interface MfaActionOptions {
  title: string
  returnTo: '/settings/emails' | '/settings/security'
  success: string
  signsOut?: boolean
}

export interface PendingMfaAction extends MfaActionOptions {
  id: number
  session: string
}

export interface MfaFlow {
  pending: PendingMfaAction | null
  run: (perform: () => Promise<void>, options: MfaActionOptions) => Promise<boolean>
  complete: () => Promise<void>
  cancel: () => void
}

export const MfaContext = createContext<MfaFlow | null>(null)

export function useMfa(): MfaFlow {
  const flow = useContext(MfaContext)
  if (!flow) throw new Error('MFA provider is required')
  return flow
}
