import {
  WalletInterface,
  IdentityClient,
  Utils,
  Random,
  MasterCertificate,
  WalletClient,
  VerifiableCertificate,
  type WalletCertificate
} from '@bsv/sdk'
import { DIDClient } from '@bsv/did-client'
import { MessageBoxClient } from '@bsv/message-box-client'
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
  RevokeResult
} from './types'

/**
 * PeerCert provides high-level workflows for peer-to-peer certificates on BSV.
 * 
 * @example
 * ```typescript
 * import { WalletClient, Utils } from '@bsv/sdk'
 * import { PeerCert } from '@bsv/peercert'
 * 
 * const wallet = new WalletClient()
 * const peercert = new PeerCert(wallet)
 * 
 * // Issue a certificate
 * const result = await peercert.issue({
 *   certificateType: Utils.toBase64(Utils.toArray('employment', 'utf8')),
 *   subjectIdentityKey: '03abc...',
 *   fields: { role: 'Engineer', company: 'ACME Corp' }
 * })
 * 
 * // The serialized certificate can be sent via any channel (messagebox, QR, etc)
 * console.log('Send this:', result.serializedCertificate)
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
   * Returns both the master certificate metadata and the serialized certificate
   * for transmission to the subject.
   * 
   * @param options - Certificate issuance options
   * @returns Promise resolving to the issued certificate result
   * 
   * @example
   * ```typescript
   * const result = await peercert.issue({
   *   certificateType: Utils.toBase64(Utils.toArray('skill', 'utf8')),
   *   subjectIdentityKey: '03abc123...',
   *   fields: { 
   *     javascript: 'expert',
   *     typescript: 'advanced'
   *   }
   * })
   * 
   * console.log('Serial:', result.masterCertificate.serialNumber)
   * console.log('Send this:', result.serializedCertificate)
   * ```
   */
  async issue(options: IssueOptions): Promise<MasterCertificate> {
    const { certificateType, subjectIdentityKey, fields, autoSend } = options

    // Validate inputs
    if (!subjectIdentityKey || typeof subjectIdentityKey !== 'string') {
      throw new Error('Valid subject public key is required')
    }
    if (!certificateType || typeof certificateType !== 'string') {
      throw new Error('Certificate type is required')
    }
    if (!fields || typeof fields !== 'object' || Object.keys(fields).length === 0) {
      throw new Error('At least one field is required')
    }

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
   * Accepts either a serialized certificate string or a MasterCertificate object.
   * Verifies the signature and stores it in your wallet. The wallet will automatically
   * decrypt the fields using your identity key.
   * 
   * @param certificate - Serialized certificate string or MasterCertificate object
   * @returns Promise resolving to the receive result
   * 
   * @example
   * ```typescript
   * // From string
   * const result = await peercert.receive(serializedCertString)
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
  async receive(certificate: string | MasterCertificate): Promise<ReceiveResult> {
    try {
      // Parse the certificate if it's a string
      const certData = typeof certificate === 'string'
        ? JSON.parse(certificate)
        : certificate

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
        certData.keyring,
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
        keyringForSubject: certData.keyring,
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
   * @param certificate - The certificate to check revocation status for
   * @returns Promise resolving to revocation status
   * 
   * @example
   * ```typescript
   * const status = await peercert.checkRevocation(myCertificate)
   * 
   * if (status.isRevoked) {
   *   console.log('Certificate has been revoked!')
   * } else {
   *   console.log('Certificate is still valid')
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
        isRevoked,
        revocationOutpoint: certificate.revocationOutpoint,
        message: isRevoked
          ? 'Certificate has been revoked (DID token spent or not found)'
          : 'Certificate is valid (DID token exists)'
      }
    } catch (error) {
      // If query fails, we can't determine status
      return {
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
      try {
        // Parse the message wrapper
        const parsed = JSON.parse(msg.body as string)

        return {
          serializedCertificate: parsed.serializedCertificate,
          messageId: msg.messageId,
          sender: msg.sender,
          issuance: parsed.issuance ?? true  // Default to true for backward compatibility
        }
      } catch (error) {
        // If parsing fails, assume old format (raw certificate = issuance)
        return {
          serializedCertificate: msg.body as string,
          messageId: msg.messageId,
          sender: msg.sender,
          issuance: true
        }
      }
    })
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
        try {
          // Parse the message wrapper
          const parsed = JSON.parse(message.body as string)
          await onCertificate(
            parsed.serializedCertificate,
            message.messageId,
            message.sender,
            parsed.issuance ?? true
          )
        } catch (error) {
          // If parsing fails, assume old format (raw certificate = issuance)
          await onCertificate(message.body as string, message.messageId, message.sender, true)
        }
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

    // Type guard to check if certificate has keyring (from certifiersRequired: true)
    if (!('keyringForSubject' in certificate)) {
      throw new Error(
        'Certificate must include keyring. Get it from wallet.listCertificates() with certifiersRequired: true'
      )
    }

    const certWithKeyring = certificate as WalletCertificate & {
      keyringForSubject: Record<string, string>
    }

    // Create keyring for the verifier using the MasterCertificate static method
    const keyringForVerifier = await MasterCertificate.createKeyringForVerifier(
      this.wallet,
      certWithKeyring.certifier,
      verifierPublicKey,
      certWithKeyring.fields,
      fieldsToReveal,
      certWithKeyring.keyringForSubject,
      certWithKeyring.serialNumber
    )

    // Create and return the VerifiableCertificate
    return new VerifiableCertificate(
      certWithKeyring.type,
      certWithKeyring.serialNumber,
      certWithKeyring.subject,
      certWithKeyring.certifier,
      certWithKeyring.revocationOutpoint,
      certWithKeyring.fields,
      keyringForVerifier,
      certWithKeyring.signature
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
   * @param serializedCertificate - Serialized verifiable certificate
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
   *   if (result.verified) {
   *     if (result.revocationStatus?.isRevoked) {
   *       console.log(' Certificate has been revoked!')
   *     } else {
   *       console.log(' Certificate is valid')
   *       console.log('Revealed fields:', result.fields)
   *     }
   *     await peercert.acknowledgeCertificate(cert.messageId)
   *   }
   * }
   * ```
   */
  async verifyVerifiableCertificate(
    serializedCertificate: string,
    options?: VerifyVerifiableCertificateOptions
  ): Promise<VerifyVerifiableCertificateResult> {
    try {
      // Parse the verifiable certificate
      const certData = JSON.parse(serializedCertificate)

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
