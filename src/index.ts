/**
 * peercert - Peer-to-peer certificate workflows for BSV blockchain
 * 
 * High-level API for issuing, receiving, and publicly revealing
 * peer-to-peer certificates on the BSV blockchain.
 * 
 * @packageDocumentation
 * 
 * @example
 * ```typescript
 * import { WalletClient, Utils } from '@bsv/sdk'
 * import { PeerCert } from 'peercert'
 * 
 * const wallet = new WalletClient()
 * const peercert = new PeerCert(wallet)
 * 
 * // Issue a certificate (human-readable type names are normalized automatically)
 * const cert = await peercert.issue({
 *   certificateType: 'employment',
 *   subjectIdentityKey: '03abc...',
 *   fields: { role: 'Engineer', company: 'ACME Corp' }
 * })
 * 
 * // Receive a certificate
 * const received = await peercert.receive(serializedCertificate)
 * 
 * // Publicly reveal selected fields
 * await peercert.reveal({
 *   certificate: received.walletCertificate,
 *   fieldsToReveal: ['role']
 * })
 * ```
 */

export { PeerCert } from './PeerCert.js'

export {
  encodeCertificate,
  decodeCertificate,
  estimateEncodedSize,
  type DecodedCertificate
} from './serialization.js'

export type {
  PeerCertOptions,
  IssueOptions,
  ReceiveResult,
  RevealOptions,
  RevealResult,
  SendOptions,
  IncomingCertificate,
  CreateVerifiableCertificateOptions,
  VerifyVerifiableCertificateOptions,
  VerifyVerifiableCertificateResult,
  RevocationStatus,
  RevokeResult,
  ListCertificatesOptions
} from './types.js'
