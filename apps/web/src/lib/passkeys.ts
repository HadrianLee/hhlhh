import { mutate } from './api'
import type { AuthenticationChallenge, RegistrationChallenge } from './types'

export async function signInWithPasskey(): Promise<void> {
  if (!passkeySupported()) throw new Error('Passkeys need HTTPS and a supported browser.')
  const created = await mutate<Pick<AuthenticationChallenge, 'challenge_id' | 'public_key'>>('/api/auth/passkey/options')
  const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(created.public_key) })
  if (!(credential instanceof PublicKeyCredential)) throw new Error('The passkey request was cancelled or no credential was returned.')
  await mutate('/api/auth/passkey/login', { challenge_id: created.challenge_id, credential: credential.toJSON() })
}

export function passkeySupported(): boolean {
  return window.isSecureContext && typeof PublicKeyCredential !== 'undefined'
    && typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function'
    && typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function'
    && typeof PublicKeyCredential.prototype.toJSON === 'function'
}

export async function passkey(enroll: boolean): Promise<void> {
  if (!passkeySupported()) throw new Error('Passkeys need HTTPS and a supported browser.')
  let credential: Credential | null
  let id: string
  if (enroll) {
    const created = await mutate<RegistrationChallenge>('/api/identity/challenges/passkey-registration')
    id = created.challenge_id
    credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(created.public_key) })
  } else {
    const created = await mutate<AuthenticationChallenge>('/api/identity/challenges/passkey-authentication')
    id = created.challenge_id
    credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(created.public_key) })
  }
  if (!(credential instanceof PublicKeyCredential)) throw new Error('The passkey request was cancelled or no credential was returned.')
  await mutate(`/api/identity/challenges/${id}/verify`, {
    method: enroll ? 'passkey_registration' : 'passkey_authentication', credential: credential.toJSON(),
  })
}
