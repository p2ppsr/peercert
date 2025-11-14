import type {
  WalletCertificate,
  CertificateFieldNameUnder50Bytes,
  BroadcastResponse,
  BroadcastFailure,
  PubKeyHex
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
  certificateType: string

  /** Public key of the certificate subject */
  subjectPublicKey: string

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
}

