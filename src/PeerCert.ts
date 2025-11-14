import {
  WalletInterface,
  IdentityClient,
  Utils,
  Random,
  MasterCertificate,
  WalletClient
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
  IncomingCertificate
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
 *   subjectPublicKey: '03abc...',
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
   *   subjectPublicKey: '03abc123...',
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
    const { certificateType, subjectPublicKey, fields, autoSend } = options

    // Validate inputs
    if (!subjectPublicKey || typeof subjectPublicKey !== 'string') {
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
      subjectPublicKey,
      serialNumber
    )

    // Create the master certificate using SDK
    const masterCert = await MasterCertificate.issueCertificateForSubject(
      this.wallet,
      subjectPublicKey,
      fields,
      certificateType,
      async () => revocationOutpoint,
      serialNumber
    )

    // Auto-send via MessageBox if requested
    if (autoSend) {
      await this.send({
        recipient: subjectPublicKey,
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
   * Send a certificate to a recipient via MessageBox
   * 
   * @param options - Send options
   * 
   * @example
   * ```typescript
   * await peercert.send({
   *   recipient: '03abc...',
   *   serializedCertificate: JSON.stringify(masterCert)
   * })
   * ```
   */
  async send(options: SendOptions): Promise<void> {
    await this.getMessageBoxClient().sendMessage({
      recipient: options.recipient,
      messageBox: PeerCert.PEERCERT_MESSAGEBOX,
      body: options.serializedCertificate
    })
  }

  /**
   * List incoming certificates from your MessageBox
   * 
   * @returns Array of incoming certificates
   * 
   * @example
   * ```typescript
   * const incoming = await peercert.listIncomingCertificates()
   * for (const cert of incoming) {
   *   console.log('From:', cert.sender)
   *   const result = await peercert.receive(cert.serializedCertificate)
   *   if (result.success) {
   *     await peercert.acknowledgeCertificate(cert.messageId)
   *   }
   * }
   * ```
   */
  async listIncomingCertificates(): Promise<IncomingCertificate[]> {
    const messages = await this.getMessageBoxClient().listMessages({
      messageBox: PeerCert.PEERCERT_MESSAGEBOX
    })

    return messages.map(msg => ({
      serializedCertificate: msg.body as string,
      messageId: msg.messageId,
      sender: msg.sender
    }))
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
   * await peercert.listenForCertificates(async (serializedCertificate, messageId, sender) => {
   *   console.log('New certificate from:', sender)
   *   const result = await peercert.receive(serializedCertificate)
   *   if (result.success) {
   *     await peercert.acknowledgeCertificate(messageId)
   *   }
   * })
   * ```
   */
  async listenForCertificates(
    onCertificate: (serializedCertificate: string, messageId: string, sender: string) => void | Promise<void>
  ): Promise<void> {
    await this.getMessageBoxClient().listenForLiveMessages({
      messageBox: PeerCert.PEERCERT_MESSAGEBOX,
      onMessage: async (message) => {
        await onCertificate(message.body as string, message.messageId, message.sender)
      }
    })
  }

  /**
   * Create a revocation outpoint for a certificate using DID
   * @private
   */
  private async createRevocationOutpoint(
    subjectPublicKey: string,
    serialNumber: string
  ): Promise<string> {
    const response = await this.didClient.createDID(
      serialNumber,
      subjectPublicKey
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
