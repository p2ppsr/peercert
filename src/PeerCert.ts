import {
  WalletInterface,
  IdentityClient,
  Utils,
  Random,
  Hash,
  MasterCertificate,
  WalletClient,
  VerifiableCertificate,
  type WalletCertificate
} from '@bsv/sdk'
import { DIDClient } from '@bsv/did-client'
import { MessageBoxClient } from '@bsv/message-box-client'
import { encodeCertificate, decodeCertificate, type DecodedCertificate } from './serialization'
import type {
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
} from './types'

/**
 * PeerCert provides high-level workflows for peer-to-peer certificates on BSV.
 * 
 * @example
 * ```typescript
 * import { WalletClient } from '@bsv/sdk'
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
 * // The certificate can be sent via any channel (MessageBox, QR, NFC, files)
 * console.log('Send this:', JSON.stringify(cert))
 * // Or compact binary for QR codes:
 * console.log('QR data:', PeerCert.encodeCertificate(cert))
 * ```
 */
export class PeerCert {
  private readonly identityClient: IdentityClient
  private readonly didClient: DIDClient
  private messageBoxClient?: MessageBoxClient
  private readonly wallet: WalletInterface
  private readonly options: PeerCertOptions
  private myIdentityKey?: string
  private static readonly PEERCERT_MESSAGEBOX = 'peercert'

  /**
   * Lazy-initialize MessageBoxClient only when needed
   */
  private getMessageBoxClient(): MessageBoxClient {
    if (!this.messageBoxClient) {
      this.messageBoxClient = new MessageBoxClient({
        host: this.options.messageBoxHost ?? 'https://messagebox.babbage.systems',
        walletClient: this.wallet,
        enableLogging: this.options.enableMessageBoxLogging ?? false
      })
    }
    return this.messageBoxClient
  }

  /**
   * Lazy-initialize identity key only when needed
   */
  private async getMyIdentityKey(): Promise<string> {
    if (!this.myIdentityKey) {
      const { publicKey } = await this.wallet.getPublicKey({
        identityKey: true
      })
      this.myIdentityKey = publicKey
    }
    return this.myIdentityKey
  }

  /**
   * Create a new PeerCert instance
   * 
   * @param wallet - Optional wallet interface to use for operations
   * @param options - Optional configuration
   */
  constructor(
    wallet?: WalletInterface,
    options?: PeerCertOptions
  ) {
    this.options = options ?? {}
    this.wallet = wallet ?? new WalletClient()
    this.identityClient = new IdentityClient(this.wallet)
    this.didClient = new DIDClient({
      wallet: this.wallet,
      acceptDelayedBroadcast: false,
      networkPreset: options?.networkPreset ?? 'mainnet'
    })
  }

  /**
   * Issue a new certificate to a peer
   *
   * Creates a certificate with encrypted fields that only the subject can decrypt.
   * Returns the signed MasterCertificate, ready for transmission to the subject
   * (via autoSend, send(), JSON, or PeerCert.encodeCertificate for QR/NFC).
   *
   * The certificate type may be a base64 identifier (used as-is) or any
   * human-readable name (e.g. 'employment'), which is deterministically
   * normalized via {@link PeerCert.certificateTypeFromName}.
   *
   * @param options - Certificate issuance options
   * @returns Promise resolving to the issued MasterCertificate
   *
   * @example
   * ```typescript
   * const cert = await peercert.issue({
   *   certificateType: 'skill',
   *   subjectIdentityKey: '03abc123...',
   *   fields: {
   *     javascript: 'expert',
   *     typescript: 'advanced'
   *   },
   *   autoSend: true // deliver via MessageBox
   * })
   *
   * console.log('Serial:', cert.serialNumber)
   * ```
   */
  async issue(options: IssueOptions): Promise<MasterCertificate> {
    const { subjectIdentityKey, fields, autoSend } = options

    // Validate inputs
    if (!subjectIdentityKey || typeof subjectIdentityKey !== 'string') {
      throw new Error('Valid subject public key is required')
    }
    if (!options.certificateType || typeof options.certificateType !== 'string') {
      throw new Error('Certificate type is required')
    }
    if (!fields || typeof fields !== 'object' || Object.keys(fields).length === 0) {
      throw new Error('At least one field is required')
    }

    const certificateType = PeerCert.normalizeCertificateType(options.certificateType)

    // Generate serial number
    const serialNumber = Utils.toBase64(Random(32))

    // Create revocation outpoint using DID
    const revocationOutpoint = await this.createRevocationOutpoint(
      subjectIdentityKey,
      serialNumber
    )

    // Create the master certificate using SDK
    const masterCert = await MasterCertificate.issueCertificateForSubject(
      this.wallet,
      subjectIdentityKey,
      fields,
      certificateType,
      async () => revocationOutpoint,
      serialNumber
    )

    // Auto-send via MessageBox if requested
    if (autoSend) {
      await this.send({
        recipient: subjectIdentityKey,
        serializedCertificate: JSON.stringify(masterCert)
      })
    }

    return masterCert
  }

  /**
   * Receive and store a certificate sent to you
   * 
   * Accepts any of the formats a certificate can arrive in:
   * - JSON string (from MessageBox or JSON.stringify(cert))
   * - Compact base64 string (from PeerCert.encodeCertificate, e.g. QR codes/URLs)
   * - Raw binary Uint8Array (e.g. from NFC tags or files)
   * - MasterCertificate or decoded certificate object
   *
   * Verifies the signature and stores it in your wallet. The wallet will automatically
   * decrypt the fields using your identity key.
   *
   * @param certificate - The certificate in any supported format
   * @returns Promise resolving to the receive result
   *
   * @example
   * ```typescript
   * // From JSON string
   * const result = await peercert.receive(serializedCertString)
   *
   * // From a QR code (compact base64)
   * const result = await peercert.receive(qrData.replace('peercert:', ''))
   *
   * // From object
   * const result = await peercert.receive(masterCertificate)
   *
   * if (result.success) {
   *   console.log('Certificate stored in wallet')
   *   console.log('Certifier:', result.walletCertificate.certifier)
   * }
   * ```
   */
  async receive(certificate: string | Uint8Array | MasterCertificate | DecodedCertificate): Promise<ReceiveResult> {
    try {
      // Normalize the input into certificate data
      let certData: any
      if (typeof certificate === 'string') {
        const trimmed = certificate.trim()
        certData = trimmed.startsWith('{')
          ? JSON.parse(trimmed)
          : decodeCertificate(trimmed) // compact base64 (QR/URL/file)
      } else if (certificate instanceof Uint8Array) {
        certData = decodeCertificate(certificate) // raw binary (NFC/file)
      } else {
        certData = certificate
      }

      // Verify the certificate subject matches our identity key
      const myIdentityKey = await this.getMyIdentityKey()

      if (certData.subject !== myIdentityKey) {
        return {
          success: false,
          error: 'Certificate subject does not match your identity key. This certificate is not for you.'
        }
      }

      // Verify the certificate signature
      const cert = new MasterCertificate(
        certData.type,
        certData.serialNumber,
        certData.subject,
        certData.certifier,
        certData.revocationOutpoint,
        certData.fields,
        certData.masterKeyring,
        certData.signature
      )

      await cert.verify()

      // Store via wallet's acquire certificate method
      const walletCertificate = await this.wallet.acquireCertificate({
        type: certData.type,
        certifier: certData.certifier,
        serialNumber: certData.serialNumber,
        revocationOutpoint: certData.revocationOutpoint,
        fields: certData.fields,
        signature: certData.signature,
        keyringForSubject: certData.masterKeyring,
        keyringRevealer: 'certifier',
        acquisitionProtocol: 'direct'
      }, this.options.originator)

      return {
        success: true,
        walletCertificate
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    }
  }

  /**
   * Publicly reveal certificate attributes to the overlay network
   * 
   * Creates a publicly verifiable version of your certificate with selected
   * fields revealed. This makes the certificate discoverable by others through
   * overlay services.
   * 
   * @param options - Reveal options
   * @returns Promise resolving to the broadcast result
   * 
   * @example
   * ```typescript
   * // Get your certificate from wallet
   * const certs = await wallet.listCertificates({ 
   *   certifiers: ['03def...'],
   *   limit: 1
   * })
   * 
   * // Reveal only specific fields publicly
   * const result = await peercert.reveal({
   *   certificate: certs.certificates[0],
   *   fieldsToReveal: ['javascript', 'typescript']
   *   // 'portfolio' remains private
   * })
   * 
   * if (result.status === 'success') {
   *   console.log('Certificate is now publicly discoverable!')
   * }
   * ```
   */
  async reveal(options: RevealOptions): Promise<RevealResult> {
    return await this.identityClient.publiclyRevealAttributes(
      options.certificate,
      options.fieldsToReveal
    )
  }

  /**
   * Check if a certificate has been revoked
   * 
   * Queries the DID overlay network to determine if the certificate's
   * revocation outpoint has been spent (revoked) or is still unspent (valid).
   *
   * SECURITY: If the overlay lookup fails (e.g. network error), the result
   * has `status: 'unknown'` — the certificate is NOT confirmed valid. In
   * trust-sensitive flows, only accept a certificate when `status === 'valid'`.
   *
   * @param certificate - The certificate to check revocation status for
   * @returns Promise resolving to revocation status
   *
   * @example
   * ```typescript
   * const status = await peercert.checkRevocation(myCertificate)
   *
   * if (status.status === 'valid') {
   *   console.log('Certificate is still valid')
   * } else if (status.status === 'revoked') {
   *   console.log('Certificate has been revoked!')
   * } else {
   *   console.log('Could not determine revocation status:', status.message)
   * }
   * ```
   */
  async checkRevocation(certificate: WalletCertificate): Promise<RevocationStatus> {
    try {
      // Query the DID overlay for the revocation outpoint
      const results = await this.didClient.findDID({
        outpoint: certificate.revocationOutpoint,
        limit: 1
      })

      // If the DID token exists (unspent), certificate is NOT revoked
      // If it doesn't exist or was spent, it IS revoked
      const isRevoked = results.length === 0

      return {
        status: isRevoked ? 'revoked' : 'valid',
        isRevoked,
        revocationOutpoint: certificate.revocationOutpoint,
        message: isRevoked
          ? 'Certificate has been revoked (DID token spent or not found)'
          : 'Certificate is valid (DID token exists)'
      }
    } catch (error) {
      // Lookup failed: revocation cannot be determined either way. Report
      // 'unknown' rather than claiming the certificate is valid.
      return {
        status: 'unknown',
        isRevoked: false,
        revocationOutpoint: certificate.revocationOutpoint,
        message: `Unable to verify revocation status: ${error instanceof Error ? error.message : 'Unknown error'}`
      }
    }
  }

  /**
   * Revoke a certificate that you issued
   * 
   * Spends the DID revocation token to mark the certificate as revoked.
   * This is irreversible - once revoked, the certificate cannot be un-revoked.
   * 
   * Note: You must be the original issuer (certifier) to revoke a certificate.
   * 
   * @param certificate - The certificate to revoke (that you issued)
   * @returns Promise resolving to revocation result
   * 
   * @example
   * ```typescript
   * // Revoke a certificate you issued
   * const result = await peercert.revoke(issuedCertificate)
   * 
   * if (result.success) {
   *   console.log('Certificate revoked! TXID:', result.txid)
   * } else {
   *   console.error('Failed to revoke:', result.error)
   * }
   * ```
   */
  async revoke(certificate: WalletCertificate): Promise<RevokeResult> {
    const response = await this.didClient.revokeDID({
      serialNumber: certificate.serialNumber,
      outpoint: certificate.revocationOutpoint
    })

    if (response.status === 'success') {
      return {
        success: true,
        txid: response.txid,
        revocationOutpoint: certificate.revocationOutpoint
      }
    } else {
      return {
        success: false,
        revocationOutpoint: certificate.revocationOutpoint,
        error: response.description || 'Unknown error'
      }
    }
  }

  /**
   * Send a certificate to a recipient via MessageBox
   * 
   * @param options - Send options
   * 
   * @example
   * ```typescript
   * // Send issued certificate
   * await peercert.send({
   *   recipient: '03abc...',
   *   serializedCertificate: JSON.stringify(masterCert),
   *   issuance: true  // default
   * })
   * 
   * // Send verifiable certificate for inspection
   * await peercert.send({
   *   recipient: '03abc...',
   *   serializedCertificate: JSON.stringify(verifiableCert),
   *   issuance: false
   * })
   * ```
   */
  async send(options: SendOptions): Promise<void> {
    // Wrap certificate with issuance flag
    const message = {
      serializedCertificate: options.serializedCertificate,
      issuance: options.issuance ?? true  // Default to issuance
    }

    await this.getMessageBoxClient().sendMessage({
      recipient: options.recipient,
      messageBox: PeerCert.PEERCERT_MESSAGEBOX,
      body: JSON.stringify(message)
    })
  }

  /**
   * List incoming certificates from your MessageBox
   * 
   * @returns Array of incoming certificates with issuance flag
   * 
   * @example
   * ```typescript
   * const incoming = await peercert.listIncomingCertificates()
   * for (const cert of incoming) {
   *   if (cert.issuance) {
   *     // Certificate issued TO me - store it
   *     const result = await peercert.receive(cert.serializedCertificate)
   *     if (result.success) {
   *       await peercert.acknowledgeCertificate(cert.messageId)
   *     }
   *   } else {
   *     // Certificate shared FOR inspection - verify it
   *     const result = await peercert.verifyVerifiableCertificate(cert.serializedCertificate)
   *     if (result.success) {
   *       console.log('Revealed fields:', result.decryptedFields)
   *       await peercert.acknowledgeCertificate(cert.messageId)
   *     }
   *   }
   * }
   * ```
   */
  async listIncomingCertificates(): Promise<IncomingCertificate[]> {
    const messages = await this.getMessageBoxClient().listMessages({
      messageBox: PeerCert.PEERCERT_MESSAGEBOX
    })

    return messages.map(msg => {
      const { serializedCertificate, issuance } = PeerCert.unwrapMessageBody(msg.body)
      return {
        serializedCertificate,
        messageId: msg.messageId,
        sender: msg.sender,
        issuance
      }
    })
  }

  /**
   * Unwrap a MessageBox message body into certificate payload + issuance flag.
   * Supports the { serializedCertificate, issuance } wrapper written by send()
   * and the legacy format where the body is the raw certificate itself.
   * @private
   */
  private static unwrapMessageBody(body: unknown): { serializedCertificate: string, issuance: boolean } {
    try {
      const parsed = typeof body === 'string'
        ? JSON.parse(body)
        : body as Record<string, any>

      if (parsed && typeof parsed === 'object' && 'serializedCertificate' in parsed) {
        return {
          serializedCertificate: parsed.serializedCertificate,
          issuance: parsed.issuance ?? true // Default to true for backward compatibility
        }
      }
    } catch {
      // Not JSON: fall through to legacy handling
    }
    // Legacy format: the body is the raw certificate itself (an issuance)
    return { serializedCertificate: body as string, issuance: true }
  }

  /**
   * Acknowledge a certificate message in MessageBox (marks it as read/processed)
   * 
   * @param messageId - The message ID to acknowledge
   * 
   * @example
   * ```typescript
   * await peercert.acknowledgeCertificate(messageId)
   * ```
   */
  async acknowledgeCertificate(messageId: string): Promise<void> {
    await this.getMessageBoxClient().acknowledgeMessage({
      messageIds: [messageId]
    })
  }

  /**
   * Listen for live certificate messages from MessageBox
   * 
   * @param onCertificate - Callback function when a certificate is received
   * 
   * @example
   * ```typescript
   * await peercert.listenForCertificates(async (serializedCertificate, messageId, sender, issuance) => {
   *   if (issuance) {
   *     // Certificate issued to me
   *     const result = await peercert.receive(serializedCertificate)
   *     if (result.success) {
   *       await peercert.acknowledgeCertificate(messageId)
   *     }
   *   } else {
   *     // Certificate shared for inspection
   *     const result = await peercert.verifyVerifiableCertificate(serializedCertificate)
   *     if (result.success) {
   *       console.log('Revealed:', result.decryptedFields)
   *       await peercert.acknowledgeCertificate(messageId)
   *     }
   *   }
   * })
   * ```
   */
  async listenForCertificates(
    onCertificate: (serializedCertificate: string, messageId: string, sender: string, issuance: boolean) => void | Promise<void>
  ): Promise<void> {
    await this.getMessageBoxClient().listenForLiveMessages({
      messageBox: PeerCert.PEERCERT_MESSAGEBOX,
      onMessage: async (message) => {
        // Unwrap first, then invoke the callback exactly once — a throwing
        // callback must not be retried with differently-shaped arguments.
        const { serializedCertificate, issuance } = PeerCert.unwrapMessageBody(message.body)
        await onCertificate(serializedCertificate, message.messageId, message.sender, issuance)
      }
    })
  }

  /**
   * Create a verifiable certificate to share with a specific verifier
   * 
   * This creates a version of your certificate where only selected fields
   * can be decrypted by the verifier. The verifier can inspect the certificate
   * but it won't be stored in their wallet - they're just viewing it.
   * 
   * Note: The certificate must include the keyring. Get it from wallet.listCertificates()
   * with certifiersRequired: true option.
   * 
   * @param options - Verifiable certificate creation options
   * @returns Promise resolving to a VerifiableCertificate to send to the verifier
   * 
   * @example
   * ```typescript
   * // Get certificate with keyring
   * const certs = await wallet.listCertificates({
   *   certifiers: [certifierPubKey],
   *   types: [certType],
   *   certifiersRequired: true,
   *   limit: 1
   * })
   * 
   * // Create verifiable cert revealing only name and role
   * const verifiableCert = await peercert.createVerifiableCertificate({
   *   certificate: certs[0],
   *   verifierPublicKey: '03abc...',
   *   fieldsToReveal: ['name', 'role']
   * })
   * 
   * // Send to the verifier (automatically sets issuance: false)
   * await peercert.send({
   *   recipient: '03abc...',
   *   serializedCertificate: JSON.stringify(verifiableCert),
   *   issuance: false  // Mark as sharing for inspection
   * })
   * ```
   */
  async createVerifiableCertificate(
    options: CreateVerifiableCertificateOptions
  ): Promise<VerifiableCertificate> {
    const { certificate, verifierPublicKey, fieldsToReveal } = options

    // Validate inputs
    if (!certificate) {
      throw new Error('Certificate is required')
    }
    if (!verifierPublicKey || typeof verifierPublicKey !== 'string') {
      throw new Error('Valid verifier public key is required')
    }
    if (!fieldsToReveal || fieldsToReveal.length === 0) {
      throw new Error('At least one field to reveal is required')
    }

    // Create keyring for the verifier using the MasterCertificate static method
    // Note: ts-sdk naming inconsistency - wallet.listCertificates() returns "keyring" 
    // but MasterCertificate.createKeyringForVerifier() expects "masterKeyring" parameter
    const certWithKeyring = certificate as WalletCertificate & {
      keyring: Record<string, string>
    }

    const keyringForVerifier = await MasterCertificate.createKeyringForVerifier(
      this.wallet,
      certificate.certifier,
      verifierPublicKey,
      certificate.fields,
      fieldsToReveal,
      certWithKeyring.keyring,  // This IS the master keyring, just named differently
      certificate.serialNumber
    )

    // Create and return the VerifiableCertificate
    return new VerifiableCertificate(
      certificate.type,
      certificate.serialNumber,
      certificate.subject,
      certificate.certifier,
      certificate.revocationOutpoint,
      certificate.fields,
      keyringForVerifier,
      certificate.signature
    )
  }

  /**
   * Verify and decrypt a verifiable certificate shared with you
   * 
   * Verifies the signature and decrypts the revealed fields using your wallet.
   * Optionally checks revocation status automatically.
   * This method is used when someone shares a certificate with you for inspection
   * (as opposed to issuing one to you via `receive()`).
   *
   * When `checkRevocation` is enabled and the certificate is revoked, the
   * result has `verified: false`. If the revocation lookup fails, the result
   * stays verified (signature-wise) but `revocationStatus.status` is
   * 'unknown' — treat that as unconfirmed in trust-sensitive flows.
   *
   * @param certificate - The verifiable certificate: a serialized JSON string,
   *   a VerifiableCertificate instance, or its plain-object form
   * @param options - Verification options
   * @returns Promise resolving to verification result with decrypted fields
   *
   * @example
   * ```typescript
   * const incoming = await peercert.listIncomingCertificates()
   *
   * for (const cert of incoming) {
   *   const result = await peercert.verifyVerifiableCertificate(
   *     cert.serializedCertificate,
   *     { checkRevocation: true }  // Auto-check revocation
   *   )
   *
   *   if (result.verified && result.revocationStatus?.status === 'valid') {
   *     console.log('Certificate is valid')
   *     console.log('Revealed fields:', result.fields)
   *     await peercert.acknowledgeCertificate(cert.messageId)
   *   } else {
   *     console.log('Rejected:', result.error ?? result.revocationStatus?.message)
   *   }
   * }
   * ```
   */
  async verifyVerifiableCertificate(
    certificate: string | VerifiableCertificate | Record<string, any>,
    options?: VerifyVerifiableCertificateOptions
  ): Promise<VerifyVerifiableCertificateResult> {
    try {
      // Parse the verifiable certificate if serialized
      const certData: any = typeof certificate === 'string'
        ? JSON.parse(certificate)
        : certificate

      // Create VerifiableCertificate instance
      const cert = new VerifiableCertificate(
        certData.type,
        certData.serialNumber,
        certData.subject,
        certData.certifier,
        certData.revocationOutpoint,
        certData.fields,
        certData.keyring,
        certData.signature,
        certData.decryptedFields
      )

      // Verify the signature
      await cert.verify()

      // Decrypt the revealed fields
      const fields = await cert.decryptFields(
        this.wallet,
        false,
        undefined,
        this.options.originator
      )

      const result: VerifyVerifiableCertificateResult = {
        verified: true,
        fields
      }

      // Optionally check revocation status
      if (options?.checkRevocation) {
        result.revocationStatus = await this.checkRevocation({
          revocationOutpoint: cert.revocationOutpoint
        } as WalletCertificate)

        // Fail closed: a definitively revoked certificate never verifies
        if (result.revocationStatus.status === 'revoked') {
          return {
            verified: false,
            fields,
            revocationStatus: result.revocationStatus,
            error: 'Certificate has been revoked'
          }
        }
      }

      return result
    } catch (error) {
      return {
        verified: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      }
    }
  }

  /**
   * Encode a MasterCertificate to compact binary format (base64)
   * Perfect for QR codes, NFC tags, URLs, and files
   * 
   * This is much more space-efficient than JSON:
   * - Typical JSON: ~1500-2500 bytes
   * - Binary format: ~400-800 bytes (50-70% smaller)
   * 
   * @param certificate - The MasterCertificate to encode
   * @returns Base64-encoded compact binary representation
   * 
   * @example
   * ```typescript
   * const cert = await peercert.issue({...})
   * const compact = PeerCert.encodeCertificate(cert)
   * 
   * // Use in QR code
   * const qrData = `peercert:${compact}`
   * 
   * // Use in URL
   * const url = `https://example.com/cert?data=${encodeURIComponent(compact)}`
   * 
   * // Save to file
   * fs.writeFileSync('cert.pc', compact, 'utf8')
   * ```
   */
  static encodeCertificate(certificate: MasterCertificate, outputFormat: 'binary' | 'base64' = 'base64'): string | Uint8Array {
    return encodeCertificate(certificate, outputFormat)
  }

  /**
   * Decode a compact binary certificate back to MasterCertificate data
   *
   * The format is detected from the input type: strings are treated as base64,
   * Uint8Arrays as raw binary. Decoding validates all lengths, so untrusted
   * input (QR codes, URLs, NFC) throws a clear error instead of misbehaving.
   *
   * @param encoded - Base64 string or raw binary certificate
   * @returns Certificate data that can be used to reconstruct a MasterCertificate
   *
   * @example
   * ```typescript
   * // From QR code
   * const qrData = 'peercert:AQd...'
   * const compact = qrData.replace('peercert:', '')
   * const certData = PeerCert.decodeCertificate(compact)
   *
   * // Receive it (receive() also accepts the compact string directly)
   * const result = await peercert.receive(certData)
   * ```
   */
  static decodeCertificate(encoded: string | Uint8Array): DecodedCertificate {
    return decodeCertificate(encoded)
  }

  /**
   * Derive a 32-byte base64 certificate type from a human-readable name
   *
   * Deterministic (SHA-256), so issuers and verifiers using the same name
   * always agree on the type. issue() and listCertificates() apply this
   * automatically to any type that isn't already valid base64.
   *
   * @param name - Human-readable type name, e.g. 'employment'
   * @returns Base64-encoded 32-byte certificate type
   *
   * @example
   * ```typescript
   * const employmentType = PeerCert.certificateTypeFromName('employment')
   * ```
   */
  static certificateTypeFromName(name: string): string {
    return Utils.toBase64(Hash.sha256(name, 'utf8'))
  }

  /**
   * Normalize a certificate type: syntactically valid base64 passes through
   * unchanged (existing ecosystem type IDs come in many byte lengths, and
   * rewriting them would silently orphan already-issued certificates);
   * anything that cannot be base64 is treated as a human-readable name.
   *
   * Note: short names that happen to be valid base64 (base64 alphabet only
   * and a multiple of 4 characters, e.g. 'work') pass through as-is — use
   * certificateTypeFromName() explicitly if you want such a name hashed.
   * @private
   */
  private static normalizeCertificateType(type: string): string {
    if (type.length > 0 && type.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(type)) {
      return type
    }
    return PeerCert.certificateTypeFromName(type)
  }

  /**
   * List certificates held in your wallet
   *
   * Convenience wrapper around wallet.listCertificates(). Human-readable type
   * names are normalized the same way as in issue(), so you can filter with
   * the same value you issued with.
   *
   * @param options - Optional filters (certifiers, types, limit)
   * @returns Promise resolving to the matching wallet certificates
   *
   * @example
   * ```typescript
   * // All my certificates
   * const certs = await peercert.listCertificates()
   *
   * // Employment certificates from a specific certifier
   * const certs = await peercert.listCertificates({
   *   certifiers: ['03certifier...'],
   *   types: ['employment']
   * })
   * ```
   */
  async listCertificates(options?: ListCertificatesOptions): Promise<WalletCertificate[]> {
    const { certificates } = await this.wallet.listCertificates({
      certifiers: options?.certifiers ?? [],
      types: (options?.types ?? []).map(t => PeerCert.normalizeCertificateType(t)),
      limit: options?.limit
    }, this.options.originator)
    return certificates
  }

  /**
   * Create a revocation outpoint for a certificate using DID
   * @private
   */
  private async createRevocationOutpoint(
    subjectIdentityKey: string,
    serialNumber: string
  ): Promise<string> {
    const response = await this.didClient.createDID(
      serialNumber,
      subjectIdentityKey
    )

    if (response.status === 'error') {
      throw new Error(`Failed to create revocation token: ${response.description}`)
    }

    const txid = response.txid
    if (!txid) {
      throw new Error('No txid returned from DID creation')
    }

    return `${txid}.0`
  }
}
