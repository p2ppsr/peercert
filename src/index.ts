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
 * // Issue a certificate
 * const result = await peercert.issue({
 *   certificateType: Utils.toBase64(Utils.toArray('employment', 'utf8')),
 *   subjectPublicKey: '03abc...',
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

export type {
  PeerCertOptions,
  IssueOptions,
  ReceiveResult,
  RevealOptions,
  RevealResult,
  SendOptions,
  IncomingCertificate as PendingCertificate,
  CreateVerifiableCertificateOptions,
  VerifyVerifiableCertificateOptions,
  VerifyVerifiableCertificateResult,
  RevocationStatus,
  RevokeResult
} from './types.js'
