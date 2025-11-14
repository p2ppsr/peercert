import type {
  WalletCertificate,
  CertificateFieldNameUnder50Bytes,
  BroadcastResponse,
  BroadcastFailure,
  PubKeyHex,
  Base64String
} from '@bsv/sdk'

/**
 * Options for PeerCert initialization
 */
export interface PeerCertOptions {
  /** Custom protocol ID for identity operations (defaults to IdentityClient defaults) */
  protocolID?: [number, string]

  /** Custom key ID for identity operations */
  keyID?: string

  /** Originator domain for wallet operations */
  originator?: string

  /** Network preset */
  networkPreset?: 'mainnet' | 'testnet' | 'local'

  /** MessageBox server URL (defaults to 'https://messagebox.babbage.systems') */
  messageBoxHost?: string

  /** Enable MessageBox logging for debugging */
  enableMessageBoxLogging?: boolean
}

/**
 * Options for issuing a new certificate
 */
export interface IssueOptions {
  /** Base64-encoded certificate type identifier */
  certificateType: Base64String

  /** Public key of the certificate subject */
  subjectIdentityKey: PubKeyHex

  /** Certificate fields (key-value pairs to attest) */
  fields: Record<string, string>

  /** Auto-send via MessageBox (defaults to false) */
  autoSend?: boolean
}

// IssueResult removed - issue() now returns MasterCertificate directly

/**
 * Result from receiving a certificate
 */
export interface ReceiveResult {
  /** Success status */
  success: boolean

  /** The stored wallet certificate */
  walletCertificate?: WalletCertificate

  /** Error message if failed */
  error?: string
}

/**
 * Options for publicly revealing certificate attributes
 */
export interface RevealOptions {
  /** The certificate to reveal (from wallet) */
  certificate: WalletCertificate

  /** Array of field names to publicly reveal */
  fieldsToReveal: CertificateFieldNameUnder50Bytes[]
}

/**
 * Result from publicly revealing a certificate
 */
export type RevealResult = BroadcastResponse | BroadcastFailure

/**
 * Options for sending a certificate to a recipient via MessageBox
 */
export interface SendOptions {
  /** Recipient's public key */
  recipient: PubKeyHex

  /** Serialized certificate data */
  serializedCertificate: string

  /** 
   * Whether this is an issuance (cert issued TO recipient) or sharing (cert shared FOR inspection)
   * Defaults to true (issuance)
   */
  issuance?: boolean
}

/**
 * Incoming certificate from MessageBox
 */
export interface IncomingCertificate {
  /** Serialized certificate JSON */
  serializedCertificate: string

  /** MessageBox message ID for acknowledgment */
  messageId: string

  /** Sender's identity public key */
  sender: PubKeyHex

  /** 
   * Whether this is an issuance (cert issued TO you) or sharing (cert shared FOR inspection)
   * true = use receive() to store, false = use verifyVerifiableCertificate() to inspect
   */
  issuance: boolean
}

/**
 * Options for creating a verifiable certificate to share with a specific verifier
 */
export interface CreateVerifiableCertificateOptions {
  /** The certificate from your wallet to create a verifiable version of */
  certificate: WalletCertificate

  /** Public key of the verifier who will decrypt the revealed fields */
  verifierPublicKey: PubKeyHex

  /** Fields to reveal to the verifier (other fields remain encrypted) */
  fieldsToReveal: CertificateFieldNameUnder50Bytes[]
}

/**
 * Options for verifying a verifiable certificate
 */
export interface VerifyVerifiableCertificateOptions {
  /** Whether to automatically check revocation status */
  checkRevocation?: boolean
}

/**
 * Result from verifying a verifiable certificate
 */
export interface VerifyVerifiableCertificateResult {
  /** Whether verification succeeded */
  verified: boolean

  /** The decrypted fields if verification succeeded */
  fields?: Record<string, string>

  /** Revocation status if checkRevocation was enabled */
  revocationStatus?: RevocationStatus

  /** Error message if verification failed */
  error?: string
}

/**
 * Result from checking certificate revocation status
 */
export interface RevocationStatus {
  /** Whether the certificate has been revoked */
  isRevoked: boolean

  /** The revocation outpoint that was checked */
  revocationOutpoint: string

  /** Additional details if available */
  message?: string
}

/**
 * Result from revoking a certificate
 */
export interface RevokeResult {
  /** Whether revocation succeeded */
  success: boolean

  /** Transaction ID of the revocation transaction */
  txid?: string

  /** The revocation outpoint that was spent */
  revocationOutpoint?: string

  /** Error message if revocation failed */
  error?: string
}

