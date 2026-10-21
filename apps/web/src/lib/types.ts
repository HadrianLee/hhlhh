export interface User {
  user_id: string
  email: string
  username: string
  verified_at: string | null
  created_at: string
  updated_at: string
}
export interface Session {
  session_id: string
  created_at: string
  last_used_at: string
  expires_at: string
  revoked_at: string | null
  revoke_reason: string | null
  ip_address: string | null
  user_agent: string | null
  is_current: boolean
}
export interface SessionEvent {
  event_id: string
  event_type: string
  reason: string | null
  created_at: string
}
export interface SecondaryEmail {
  secondary_email_id: string
  email: string
  is_verified: boolean
  verified_at: string | null
  created_at: string
}
export interface MfaStatus {
  verified_at: string | null
  expires_at: string | null
  method: string | null
}
export interface Challenge {
  challenge_id: string
  purpose: string
  status: 'pending' | 'verified' | 'expired' | 'exhausted' | 'cancelled'
  expires_at: string
  verified_at: string | null
  attempts_remaining: number
}
export interface RegistrationChallenge extends Challenge {
  public_key: PublicKeyCredentialCreationOptionsJSON
}
export interface AuthenticationChallenge extends Challenge {
  public_key: PublicKeyCredentialRequestOptionsJSON
}
