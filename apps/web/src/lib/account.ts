import { createContext, useContext } from 'react'
import type { Session, User } from './types'

export interface Account {
  user: User | null
  session: Session | null
  loading: boolean
  error: string
  notice: string
  reload: () => Promise<void>
  signedOut: (notice?: string) => void
}
export const AccountContext = createContext<Account | null>(null)
export function useAccount(): Account {
  const account = useContext(AccountContext)
  if (!account) throw new Error('Account provider is required')
  return account
}
