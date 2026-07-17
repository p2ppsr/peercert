import { describe, it, expect, beforeEach, jest } from '@jest/globals'

// Controllable mocks for the network clients (DID overlay + MessageBox).
// Cryptography is NOT mocked: tests below issue and verify real certificates
// using ProtoWallet, so signature/encryption paths are genuinely exercised.
const mockCreateDID = jest.fn<any>()
const mockFindDID = jest.fn<any>()
const mockRevokeDID = jest.fn<any>()
const mockSendMessage = jest.fn<any>()
const mockListMessages = jest.fn<any>()
const mockAcknowledgeMessage = jest.fn<any>()
const mockListenForLiveMessages = jest.fn<any>()
const mockPubliclyRevealAttributes = jest.fn<any>()

jest.mock('@bsv/sdk', () => {
  const actual = jest.requireActual('@bsv/sdk') as Record<string, any>
  return {
    ...actual,
    IdentityClient: jest.fn().mockImplementation(() => ({
      publiclyRevealAttributes: (...args: any[]) => mockPubliclyRevealAttributes(...args)
    }))
  }
})

jest.mock('@bsv/did-client', () => ({
  DIDClient: jest.fn().mockImplementation(() => ({
    createDID: (...args: any[]) => mockCreateDID(...args),
    findDID: (...args: any[]) => mockFindDID(...args),
    revokeDID: (...args: any[]) => mockRevokeDID(...args)
  }))
}))

jest.mock('@bsv/message-box-client', () => ({
  MessageBoxClient: jest.fn().mockImplementation(() => ({
    sendMessage: (...args: any[]) => mockSendMessage(...args),
    listMessages: (...args: any[]) => mockListMessages(...args),
    acknowledgeMessage: (...args: any[]) => mockAcknowledgeMessage(...args),
    listenForLiveMessages: (...args: any[]) => mockListenForLiveMessages(...args)
  }))
}))

import { PeerCert } from '../PeerCert'
import { encodeCertificate } from '../serialization'
import {
  ProtoWallet,
  PrivateKey,
  MasterCertificate,
  Utils,
  type WalletInterface,
  type WalletCertificate
} from '@bsv/sdk'

const DUMMY_TXID = 'aa'.repeat(32)
const DUMMY_OUTPOINT = `${DUMMY_TXID}.0`

/**
 * A wallet with real cryptography (ProtoWallet) plus stubs for the
 * storage-related methods ProtoWallet does not implement.
 */
function makeUserWallet(priv: PrivateKey): WalletInterface {
  const wallet = new ProtoWallet(priv) as any
  wallet.acquireCertificate = jest.fn<any>().mockImplementation(async (args: any) => ({ ...args }))
  wallet.listCertificates = jest.fn<any>().mockResolvedValue({ totalCertificates: 0, certificates: [] })
  return wallet as WalletInterface
}

/** Issue a real, fully signed certificate without touching the network. */
async function issueRealCert(
  certifierWallet: WalletInterface,
  subjectPub: string,
  fields: Record<string, string> = { role: 'Engineer', company: 'ACME' }
): Promise<MasterCertificate> {
  return await MasterCertificate.issueCertificateForSubject(
    certifierWallet,
    subjectPub,
    fields,
    PeerCert.certificateTypeFromName('employment'),
    async () => DUMMY_OUTPOINT
  )
}

describe('PeerCert', () => {
  let certifierKey: PrivateKey
  let subjectKey: PrivateKey
  let verifierKey: PrivateKey
  let certifierWallet: WalletInterface
  let subjectWallet: WalletInterface
  let verifierWallet: WalletInterface
  let subjectPub: string
  let verifierPub: string

  beforeEach(() => {
    jest.clearAllMocks()
    mockCreateDID.mockResolvedValue({ status: 'success', txid: DUMMY_TXID })
    mockPubliclyRevealAttributes.mockResolvedValue({ status: 'success', txid: 'mock-reveal-txid-123' })

    certifierKey = PrivateKey.fromRandom()
    subjectKey = PrivateKey.fromRandom()
    verifierKey = PrivateKey.fromRandom()
    certifierWallet = makeUserWallet(certifierKey)
    subjectWallet = makeUserWallet(subjectKey)
    verifierWallet = makeUserWallet(verifierKey)
    subjectPub = subjectKey.toPublicKey().toString()
    verifierPub = verifierKey.toPublicKey().toString()
  })

  describe('constructor', () => {
    it('should create a PeerCert instance', () => {
      const peercert = new PeerCert(certifierWallet)
      expect(peercert).toBeInstanceOf(PeerCert)
    })

    it('should accept options', () => {
      const peercert = new PeerCert(certifierWallet, { originator: 'example.com' })
      expect(peercert).toBeInstanceOf(PeerCert)
    })
  })

  describe('issue', () => {
    it('should reject empty subject public key', async () => {
      const peercert = new PeerCert(certifierWallet)
      await expect(
        peercert.issue({ certificateType: 'test-type', subjectIdentityKey: '', fields: { test: 'value' } })
      ).rejects.toThrow('Valid subject public key is required')
    })

    it('should reject invalid subject public key type', async () => {
      const peercert = new PeerCert(certifierWallet)
      await expect(
        peercert.issue({ certificateType: 'test-type', subjectIdentityKey: null as any, fields: { test: 'value' } })
      ).rejects.toThrow('Valid subject public key is required')
    })

    it('should reject empty or missing certificate type', async () => {
      const peercert = new PeerCert(certifierWallet)
      for (const certificateType of ['', null as any]) {
        await expect(
          peercert.issue({ certificateType, subjectIdentityKey: '03abc123', fields: { test: 'value' } })
        ).rejects.toThrow('Certificate type is required')
      }
    })

    it('should reject empty or null fields', async () => {
      const peercert = new PeerCert(certifierWallet)
      for (const fields of [{}, null as any]) {
        await expect(
          peercert.issue({ certificateType: 'test-type', subjectIdentityKey: '03abc123', fields })
        ).rejects.toThrow('At least one field is required')
      }
    })

    it('issues a real, verifiable certificate', async () => {
      const peercert = new PeerCert(certifierWallet)
      const cert = await peercert.issue({
        certificateType: 'employment',
        subjectIdentityKey: subjectPub,
        fields: { role: 'Engineer' }
      })

      expect(cert.subject).toBe(subjectPub)
      expect(cert.revocationOutpoint).toBe(DUMMY_OUTPOINT)
      expect(Utils.toArray(cert.serialNumber, 'base64')).toHaveLength(32)
      await expect(cert.verify()).resolves.toBeDefined()
    })

    it('normalizes human-readable certificate types deterministically', async () => {
      const peercert = new PeerCert(certifierWallet)
      const cert = await peercert.issue({
        certificateType: 'employment',
        subjectIdentityKey: subjectPub,
        fields: { role: 'Engineer' }
      })
      expect(cert.type).toBe(PeerCert.certificateTypeFromName('employment'))
    })

    it('passes 32-byte base64 certificate types through unchanged', async () => {
      const rawType = Utils.toBase64(new Array(32).fill(5))
      const peercert = new PeerCert(certifierWallet)
      const cert = await peercert.issue({
        certificateType: rawType,
        subjectIdentityKey: subjectPub,
        fields: { role: 'Engineer' }
      })
      expect(cert.type).toBe(rawType)
    })

    it('passes existing base64 types of other byte lengths through unchanged', async () => {
      // Ecosystem type IDs are not always 32 bytes; rewriting them would
      // orphan already-issued certificates (e.g. peercert-ui's 31-byte type)
      const legacyType = Utils.toBase64(Utils.toArray('peercert-skill-endorsement-v001', 'utf8'))
      const peercert = new PeerCert(certifierWallet)
      const cert = await peercert.issue({
        certificateType: legacyType,
        subjectIdentityKey: subjectPub,
        fields: { role: 'Engineer' }
      })
      expect(cert.type).toBe(legacyType)
    })

    it('auto-sends the certificate via MessageBox when requested', async () => {
      const peercert = new PeerCert(certifierWallet)
      const cert = await peercert.issue({
        certificateType: 'employment',
        subjectIdentityKey: subjectPub,
        fields: { role: 'Engineer' },
        autoSend: true
      })

      expect(mockSendMessage).toHaveBeenCalledTimes(1)
      const call = mockSendMessage.mock.calls[0][0] as any
      expect(call.recipient).toBe(subjectPub)
      expect(call.messageBox).toBe('peercert')
      const body = JSON.parse(call.body)
      expect(body.issuance).toBe(true)
      expect(JSON.parse(body.serializedCertificate).serialNumber).toBe(cert.serialNumber)
    })

    it('throws when the revocation token cannot be created', async () => {
      mockCreateDID.mockResolvedValue({ status: 'error', description: 'overlay unavailable' })
      const peercert = new PeerCert(certifierWallet)
      await expect(
        peercert.issue({ certificateType: 'employment', subjectIdentityKey: subjectPub, fields: { role: 'x' } })
      ).rejects.toThrow('Failed to create revocation token: overlay unavailable')
    })
  })

  describe('receive', () => {
    let cert: MasterCertificate
    let subjectPeerCert: PeerCert

    beforeEach(async () => {
      cert = await issueRealCert(certifierWallet, subjectPub)
      subjectPeerCert = new PeerCert(subjectWallet)
    })

    it('accepts a JSON-serialized certificate and stores it', async () => {
      const result = await subjectPeerCert.receive(JSON.stringify(cert))

      expect(result.success).toBe(true)
      expect(subjectWallet.acquireCertificate).toHaveBeenCalledTimes(1)
      const args = (subjectWallet.acquireCertificate as any).mock.calls[0][0]
      expect(args.serialNumber).toBe(cert.serialNumber)
      expect(args.keyringForSubject).toEqual(cert.masterKeyring)
      expect(args.acquisitionProtocol).toBe('direct')
    })

    it('accepts a MasterCertificate object', async () => {
      const result = await subjectPeerCert.receive(cert)
      expect(result.success).toBe(true)
    })

    it('accepts a compact base64 string (QR/URL format)', async () => {
      const compact = encodeCertificate(cert) as string
      const result = await subjectPeerCert.receive(compact)
      expect(result.success).toBe(true)
      const args = (subjectWallet.acquireCertificate as any).mock.calls[0][0]
      expect(args.serialNumber).toBe(cert.serialNumber)
    })

    it('accepts raw binary (NFC/file format)', async () => {
      const binary = encodeCertificate(cert, 'binary') as Uint8Array
      const result = await subjectPeerCert.receive(binary)
      expect(result.success).toBe(true)
    })

    it('rejects a certificate issued to someone else', async () => {
      const otherPeerCert = new PeerCert(verifierWallet)
      const result = await otherPeerCert.receive(JSON.stringify(cert))

      expect(result.success).toBe(false)
      expect(result.error).toContain('does not match your identity key')
      expect(verifierWallet.acquireCertificate).not.toHaveBeenCalled()
    })

    it('rejects a tampered certificate', async () => {
      const tampered = { ...JSON.parse(JSON.stringify(cert)) }
      tampered.fields.role = Utils.toBase64(new Array(16).fill(0))

      const result = await subjectPeerCert.receive(JSON.stringify(tampered))
      expect(result.success).toBe(false)
      expect(subjectWallet.acquireCertificate).not.toHaveBeenCalled()
    })

    it('handles malformed input gracefully', async () => {
      for (const input of ['invalid-json', '{ incomplete', '', JSON.stringify({ type: 'test' })]) {
        const result = await subjectPeerCert.receive(input)
        expect(result.success).toBe(false)
        expect(result.error).toBeDefined()
      }
    })
  })

  describe('checkRevocation', () => {
    const certStub = { revocationOutpoint: DUMMY_OUTPOINT } as WalletCertificate

    it('reports valid when the DID token exists', async () => {
      mockFindDID.mockResolvedValue([{ some: 'token' }])
      const status = await new PeerCert(subjectWallet).checkRevocation(certStub)

      expect(status.status).toBe('valid')
      expect(status.isRevoked).toBe(false)
      expect(status.revocationOutpoint).toBe(DUMMY_OUTPOINT)
    })

    it('reports revoked when the DID token is spent or missing', async () => {
      mockFindDID.mockResolvedValue([])
      const status = await new PeerCert(subjectWallet).checkRevocation(certStub)

      expect(status.status).toBe('revoked')
      expect(status.isRevoked).toBe(true)
    })

    it('reports unknown (not valid) when the lookup fails', async () => {
      mockFindDID.mockRejectedValue(new Error('network down'))
      const status = await new PeerCert(subjectWallet).checkRevocation(certStub)

      expect(status.status).toBe('unknown')
      expect(status.isRevoked).toBe(false)
      expect(status.message).toContain('network down')
    })
  })

  describe('revoke', () => {
    it('returns success with the revocation txid', async () => {
      mockRevokeDID.mockResolvedValue({ status: 'success', txid: 'revoke-txid' })
      const result = await new PeerCert(certifierWallet).revoke({
        serialNumber: 'serial',
        revocationOutpoint: DUMMY_OUTPOINT
      } as WalletCertificate)

      expect(result.success).toBe(true)
      expect(result.txid).toBe('revoke-txid')
      expect(mockRevokeDID).toHaveBeenCalledWith({ serialNumber: 'serial', outpoint: DUMMY_OUTPOINT })
    })

    it('returns the failure description on error', async () => {
      mockRevokeDID.mockResolvedValue({ status: 'error', description: 'not the issuer' })
      const result = await new PeerCert(certifierWallet).revoke({
        serialNumber: 'serial',
        revocationOutpoint: DUMMY_OUTPOINT
      } as WalletCertificate)

      expect(result.success).toBe(false)
      expect(result.error).toBe('not the issuer')
    })
  })

  describe('MessageBox transport', () => {
    it('send() wraps the certificate with an issuance flag (default true)', async () => {
      await new PeerCert(certifierWallet).send({ recipient: subjectPub, serializedCertificate: 'CERT' })

      const call = mockSendMessage.mock.calls[0][0] as any
      expect(call.messageBox).toBe('peercert')
      expect(JSON.parse(call.body)).toEqual({ serializedCertificate: 'CERT', issuance: true })
    })

    it('send() preserves issuance: false for inspection sharing', async () => {
      await new PeerCert(certifierWallet).send({
        recipient: subjectPub,
        serializedCertificate: 'CERT',
        issuance: false
      })
      expect(JSON.parse((mockSendMessage.mock.calls[0][0] as any).body).issuance).toBe(false)
    })

    it('listIncomingCertificates() unwraps wrapped, legacy, and unwrapped-JSON bodies', async () => {
      const rawCertJson = JSON.stringify({ type: 't', subject: 's' })
      mockListMessages.mockResolvedValue([
        { messageId: '1', sender: '03a', body: JSON.stringify({ serializedCertificate: 'A', issuance: false }) },
        { messageId: '2', sender: '03b', body: 'legacy-raw-cert' },
        { messageId: '3', sender: '03c', body: rawCertJson }
      ])

      const incoming = await new PeerCert(subjectWallet).listIncomingCertificates()

      expect(incoming).toEqual([
        { serializedCertificate: 'A', messageId: '1', sender: '03a', issuance: false },
        { serializedCertificate: 'legacy-raw-cert', messageId: '2', sender: '03b', issuance: true },
        { serializedCertificate: rawCertJson, messageId: '3', sender: '03c', issuance: true }
      ])
    })

    it('acknowledgeCertificate() acknowledges by message ID', async () => {
      await new PeerCert(subjectWallet).acknowledgeCertificate('msg-1')
      expect(mockAcknowledgeMessage).toHaveBeenCalledWith({ messageIds: ['msg-1'] })
    })
  })

  describe('listenForCertificates', () => {
    async function captureOnMessage(peercert: PeerCert, onCertificate: any): Promise<(msg: any) => Promise<void>> {
      let captured: any
      mockListenForLiveMessages.mockImplementation(async (opts: any) => { captured = opts.onMessage })
      await peercert.listenForCertificates(onCertificate)
      return captured
    }

    it('delivers unwrapped certificates to the callback', async () => {
      const onCertificate = jest.fn<any>()
      const onMessage = await captureOnMessage(new PeerCert(subjectWallet), onCertificate)

      await onMessage({
        messageId: 'm1',
        sender: '03a',
        body: JSON.stringify({ serializedCertificate: 'CERT', issuance: false })
      })

      expect(onCertificate).toHaveBeenCalledWith('CERT', 'm1', '03a', false)
    })

    it('handles legacy raw-certificate bodies as issuances', async () => {
      const onCertificate = jest.fn<any>()
      const onMessage = await captureOnMessage(new PeerCert(subjectWallet), onCertificate)

      await onMessage({ messageId: 'm2', sender: '03b', body: 'legacy-raw-cert' })

      expect(onCertificate).toHaveBeenCalledWith('legacy-raw-cert', 'm2', '03b', true)
    })

    it('invokes the callback exactly once even when it throws (regression)', async () => {
      const onCertificate = jest.fn<any>().mockRejectedValue(new Error('handler failed'))
      const onMessage = await captureOnMessage(new PeerCert(subjectWallet), onCertificate)

      await expect(onMessage({
        messageId: 'm3',
        sender: '03c',
        body: JSON.stringify({ serializedCertificate: 'CERT', issuance: true })
      })).rejects.toThrow('handler failed')

      // Previously a throwing callback was retried with the raw body
      expect(onCertificate).toHaveBeenCalledTimes(1)
    })
  })

  describe('selective disclosure (real crypto)', () => {
    let cert: MasterCertificate
    let subjectPeerCert: PeerCert
    let verifierPeerCert: PeerCert
    let certificateWithKeyring: any

    beforeEach(async () => {
      cert = await issueRealCert(certifierWallet, subjectPub)
      subjectPeerCert = new PeerCert(subjectWallet)
      verifierPeerCert = new PeerCert(verifierWallet)
      // Shape returned by wallet.listCertificates(): master keyring under "keyring"
      certificateWithKeyring = { ...cert, keyring: cert.masterKeyring }
    })

    it('creates a verifiable certificate revealing only selected fields', async () => {
      const verifiable = await subjectPeerCert.createVerifiableCertificate({
        certificate: certificateWithKeyring,
        verifierPublicKey: verifierPub,
        fieldsToReveal: ['role']
      })

      const result = await verifierPeerCert.verifyVerifiableCertificate(verifiable)

      expect(result.verified).toBe(true)
      expect(result.fields).toEqual({ role: 'Engineer' }) // company stays private
    })

    it('verifies a JSON-serialized verifiable certificate', async () => {
      const verifiable = await subjectPeerCert.createVerifiableCertificate({
        certificate: certificateWithKeyring,
        verifierPublicKey: verifierPub,
        fieldsToReveal: ['role', 'company']
      })

      const result = await verifierPeerCert.verifyVerifiableCertificate(JSON.stringify(verifiable))

      expect(result.verified).toBe(true)
      expect(result.fields).toEqual({ role: 'Engineer', company: 'ACME' })
    })

    it('fails verification for the wrong verifier', async () => {
      const verifiable = await subjectPeerCert.createVerifiableCertificate({
        certificate: certificateWithKeyring,
        verifierPublicKey: verifierPub,
        fieldsToReveal: ['role']
      })

      // The subject is not the intended verifier and cannot decrypt
      const result = await subjectPeerCert.verifyVerifiableCertificate(verifiable)
      expect(result.verified).toBe(false)
    })

    it('fails closed when the certificate is revoked', async () => {
      mockFindDID.mockResolvedValue([])
      const verifiable = await subjectPeerCert.createVerifiableCertificate({
        certificate: certificateWithKeyring,
        verifierPublicKey: verifierPub,
        fieldsToReveal: ['role']
      })

      const result = await verifierPeerCert.verifyVerifiableCertificate(verifiable, { checkRevocation: true })

      expect(result.verified).toBe(false)
      expect(result.error).toBe('Certificate has been revoked')
      expect(result.revocationStatus?.status).toBe('revoked')
    })

    it('verifies with revocation status when the token is valid', async () => {
      mockFindDID.mockResolvedValue([{ some: 'token' }])
      const verifiable = await subjectPeerCert.createVerifiableCertificate({
        certificate: certificateWithKeyring,
        verifierPublicKey: verifierPub,
        fieldsToReveal: ['role']
      })

      const result = await verifierPeerCert.verifyVerifiableCertificate(verifiable, { checkRevocation: true })

      expect(result.verified).toBe(true)
      expect(result.revocationStatus?.status).toBe('valid')
    })

    it('surfaces an unknown revocation status when the lookup fails', async () => {
      mockFindDID.mockRejectedValue(new Error('overlay timeout'))
      const verifiable = await subjectPeerCert.createVerifiableCertificate({
        certificate: certificateWithKeyring,
        verifierPublicKey: verifierPub,
        fieldsToReveal: ['role']
      })

      const result = await verifierPeerCert.verifyVerifiableCertificate(verifiable, { checkRevocation: true })

      expect(result.verified).toBe(true)
      expect(result.revocationStatus?.status).toBe('unknown')
    })

    it('validates createVerifiableCertificate inputs', async () => {
      await expect(subjectPeerCert.createVerifiableCertificate({
        certificate: null as any, verifierPublicKey: verifierPub, fieldsToReveal: ['role']
      })).rejects.toThrow('Certificate is required')

      await expect(subjectPeerCert.createVerifiableCertificate({
        certificate: certificateWithKeyring, verifierPublicKey: '', fieldsToReveal: ['role']
      })).rejects.toThrow('Valid verifier public key is required')

      await expect(subjectPeerCert.createVerifiableCertificate({
        certificate: certificateWithKeyring, verifierPublicKey: verifierPub, fieldsToReveal: []
      })).rejects.toThrow('At least one field to reveal is required')
    })

    it('returns verified: false for malformed input', async () => {
      const result = await verifierPeerCert.verifyVerifiableCertificate('not-json{')
      expect(result.verified).toBe(false)
      expect(result.error).toBeDefined()
    })
  })

  describe('reveal', () => {
    it('delegates to identityClient.publiclyRevealAttributes', async () => {
      const certificate = {
        type: 'test-type',
        subject: '03subject',
        certifier: '03certifier',
        serialNumber: 'abc123',
        revocationOutpoint: 'txid.0',
        signature: 'signature',
        fields: { field1: 'value1', field2: 'value2' }
      } as WalletCertificate

      const result = await new PeerCert(subjectWallet).reveal({
        certificate,
        fieldsToReveal: ['field1']
      })

      expect(mockPubliclyRevealAttributes).toHaveBeenCalledWith(certificate, ['field1'])
      expect(result).toEqual({ status: 'success', txid: 'mock-reveal-txid-123' })
    })
  })

  describe('listCertificates', () => {
    it('lists all certificates by default', async () => {
      const stored = [{ serialNumber: 'a' }]
      ;(subjectWallet.listCertificates as any).mockResolvedValue({ totalCertificates: 1, certificates: stored })

      const certs = await new PeerCert(subjectWallet).listCertificates()

      expect(certs).toBe(stored)
      expect(subjectWallet.listCertificates).toHaveBeenCalledWith(
        { certifiers: [], types: [], limit: undefined },
        undefined
      )
    })

    it('normalizes human-readable type filters like issue() does', async () => {
      await new PeerCert(subjectWallet, { originator: 'example.com' }).listCertificates({
        certifiers: ['03cert'],
        types: ['employment'],
        limit: 5
      })

      expect(subjectWallet.listCertificates).toHaveBeenCalledWith(
        {
          certifiers: ['03cert'],
          types: [PeerCert.certificateTypeFromName('employment')],
          limit: 5
        },
        'example.com'
      )
    })

    it('passes 32-byte base64 type filters through unchanged', async () => {
      const rawType = Utils.toBase64(new Array(32).fill(5))
      await new PeerCert(subjectWallet).listCertificates({ types: [rawType] })

      expect((subjectWallet.listCertificates as any).mock.calls[0][0].types).toEqual([rawType])
    })
  })

  describe('certificateTypeFromName', () => {
    it('produces a deterministic 32-byte base64 type', () => {
      const a = PeerCert.certificateTypeFromName('employment')
      const b = PeerCert.certificateTypeFromName('employment')

      expect(a).toBe(b)
      expect(Utils.toArray(a, 'base64')).toHaveLength(32)
    })

    it('produces different types for different names', () => {
      expect(PeerCert.certificateTypeFromName('employment'))
        .not.toBe(PeerCert.certificateTypeFromName('education'))
    })

    it('normalization only hashes strings that cannot be base64', async () => {
      const peercert = new PeerCert(certifierWallet)
      // Names with non-base64 characters or a non-multiple-of-4 length are hashed
      for (const name of ['employment', 'skill-endorsement', 'reputation v2']) {
        const cert = await peercert.issue({
          certificateType: name,
          subjectIdentityKey: subjectPub,
          fields: { role: 'x' }
        })
        expect(cert.type).toBe(PeerCert.certificateTypeFromName(name))
      }
      // A base64-shaped string (alphabet only, length % 4 === 0) passes through
      const ambiguous = 'work'
      const cert = await peercert.issue({
        certificateType: ambiguous,
        subjectIdentityKey: subjectPub,
        fields: { role: 'x' }
      })
      expect(cert.type).toBe(ambiguous)
    })
  })

  describe('compact encoding statics', () => {
    it('round-trips a real certificate through PeerCert.encodeCertificate/decodeCertificate', async () => {
      const cert = await issueRealCert(certifierWallet, subjectPub)
      const compact = PeerCert.encodeCertificate(cert) as string
      const decoded = PeerCert.decodeCertificate(compact)

      expect(decoded.serialNumber).toBe(cert.serialNumber)
      expect(decoded.subject).toBe(cert.subject)
      expect(decoded.fields).toEqual(cert.fields)
      expect(decoded.masterKeyring).toEqual(cert.masterKeyring)
    })
  })
})
