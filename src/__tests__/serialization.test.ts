import { describe, it, expect } from '@jest/globals'
import { Utils } from '@bsv/sdk'
import { encodeCertificate, decodeCertificate, estimateEncodedSize } from '../serialization'

/**
 * Build structurally valid certificate data for serialization tests.
 * Values are shaped correctly (32-byte serial, 33-byte compressed pubkeys,
 * hex signature) but carry no real cryptographic meaning.
 */
function makeCertData(overrides: Record<string, any> = {}): any {
  return {
    type: Utils.toBase64(new Array(32).fill(7)),
    serialNumber: Utils.toBase64(new Array(32).fill(9)),
    subject: '02' + '11'.repeat(32),
    certifier: '03' + '22'.repeat(32),
    revocationOutpoint: 'ab'.repeat(32) + '.0',
    fields: {
      role: Utils.toBase64([1, 2, 3, 4]),
      company: Utils.toBase64([5, 6, 7])
    },
    masterKeyring: {
      role: Utils.toBase64([9, 9, 9, 9, 9]),
      company: Utils.toBase64([8, 8, 8])
    },
    signature: '30' + '44'.repeat(35),
    ...overrides
  }
}

describe('serialization', () => {
  describe('round trip', () => {
    it('encodes to base64 by default and decodes back to identical data', () => {
      const cert = makeCertData()
      const encoded = encodeCertificate(cert)

      expect(typeof encoded).toBe('string')
      const decoded = decodeCertificate(encoded as string)

      expect(decoded.type).toBe(cert.type)
      expect(decoded.serialNumber).toBe(cert.serialNumber)
      expect(decoded.subject).toBe(cert.subject)
      expect(decoded.certifier).toBe(cert.certifier)
      expect(decoded.revocationOutpoint).toBe(cert.revocationOutpoint)
      expect(decoded.signature).toBe(cert.signature)
      expect(decoded.fields).toEqual(cert.fields)
      expect(decoded.masterKeyring).toEqual(cert.masterKeyring)
    })

    it('round-trips binary format (Uint8Array)', () => {
      const cert = makeCertData()
      const encoded = encodeCertificate(cert, 'binary')

      expect(encoded).toBeInstanceOf(Uint8Array)
      const decoded = decodeCertificate(encoded as Uint8Array)

      expect(decoded).toEqual(decodeCertificate(encodeCertificate(cert) as string))
    })

    it('round-trips a non-zero vout', () => {
      const cert = makeCertData({ revocationOutpoint: 'cd'.repeat(32) + '.3' })
      const decoded = decodeCertificate(encodeCertificate(cert) as string)
      expect(decoded.revocationOutpoint).toBe('cd'.repeat(32) + '.3')
    })

    it('round-trips UTF-8 field names', () => {
      const cert = makeCertData({
        fields: { 'rôle✓': Utils.toBase64([1, 2]) },
        masterKeyring: { 'rôle✓': Utils.toBase64([3, 4]) }
      })
      const decoded = decodeCertificate(encodeCertificate(cert) as string)
      expect(Object.keys(decoded.fields)).toEqual(['rôle✓'])
    })

    it('infers format from input type regardless of legacy inputFormat argument', () => {
      const cert = makeCertData()
      const base64 = encodeCertificate(cert) as string
      const binary = encodeCertificate(cert, 'binary') as Uint8Array

      // Previously these defaults conflicted between entry points; now the
      // runtime type wins and both interpretations agree.
      expect(decodeCertificate(base64, 'binary')).toEqual(decodeCertificate(base64))
      expect(decodeCertificate(binary, 'base64')).toEqual(decodeCertificate(binary))
    })
  })

  describe('estimateEncodedSize', () => {
    it('matches the actual encoded size exactly for typical certificates', () => {
      const cert = makeCertData()
      const actual = (encodeCertificate(cert, 'binary') as Uint8Array).length
      expect(estimateEncodedSize(cert)).toBe(actual)
    })
  })

  describe('encode validation', () => {
    it('rejects a serial number that is not 32 bytes', () => {
      const cert = makeCertData({ serialNumber: Utils.toBase64([1, 2, 3]) })
      expect(() => encodeCertificate(cert)).toThrow('Serial number must be 32 bytes')
    })

    it('rejects a subject pubkey that is not 33 bytes', () => {
      const cert = makeCertData({ subject: '0211' })
      expect(() => encodeCertificate(cert)).toThrow('Subject pubkey must be 33 bytes')
    })

    it('rejects a certifier pubkey that is not 33 bytes', () => {
      const cert = makeCertData({ certifier: '0322' })
      expect(() => encodeCertificate(cert)).toThrow('Certifier pubkey must be 33 bytes')
    })

    it('rejects a revocation outpoint without txid.vout format', () => {
      const cert = makeCertData({ revocationOutpoint: 'not-an-outpoint' })
      expect(() => encodeCertificate(cert)).toThrow('txid.vout')
    })

    it('rejects a revocation outpoint with a non-numeric vout', () => {
      const cert = makeCertData({ revocationOutpoint: 'ab'.repeat(32) + '.x' })
      expect(() => encodeCertificate(cert)).toThrow('vout must be a non-negative integer')
    })

    it('rejects a missing signature', () => {
      const cert = makeCertData({ signature: '' })
      expect(() => encodeCertificate(cert)).toThrow('must have a signature')
    })

    it('rejects a field with no master keyring entry', () => {
      const cert = makeCertData()
      delete cert.masterKeyring.company
      expect(() => encodeCertificate(cert)).toThrow('Missing master keyring entry for field "company"')
    })
  })

  describe('decode hardening (untrusted input)', () => {
    it('rejects an unsupported version byte', () => {
      const binary = Array.from(encodeCertificate(makeCertData(), 'binary') as Uint8Array)
      binary[0] = 2
      expect(() => decodeCertificate(binary)).toThrow('Unsupported certificate format version: 2')
    })

    it('rejects empty input', () => {
      expect(() => decodeCertificate('')).toThrow('Malformed certificate')
      expect(() => decodeCertificate(new Uint8Array(0))).toThrow('Malformed certificate')
    })

    it('rejects every possible truncation of a valid certificate', () => {
      const full = Array.from(encodeCertificate(makeCertData(), 'binary') as Uint8Array)
      for (let length = 0; length < full.length; length++) {
        expect(() => decodeCertificate(full.slice(0, length))).toThrow()
      }
    })

    it('rejects a declared length that exceeds the available data', () => {
      // Version byte, then a type length claiming 1000 bytes with none present
      const writer = new Utils.Writer()
      writer.write([1])
      writer.writeVarIntNum(1000)
      expect(() => decodeCertificate(writer.toArray())).toThrow('exceeds remaining data')
    })

    it('rejects a field count above the maximum instead of looping', () => {
      // Valid certificate with zero fields, then overwrite the trailing
      // field count with a huge VarInt
      const noFields = makeCertData({ fields: {}, masterKeyring: {} })
      const binary = Array.from(encodeCertificate(noFields, 'binary') as Uint8Array)
      expect(binary[binary.length - 1]).toBe(0) // trailing zero field count
      binary.pop()

      const writer = new Utils.Writer()
      writer.write(binary)
      writer.writeVarIntNum(100000)
      expect(() => decodeCertificate(writer.toArray())).toThrow('exceeds maximum')
    })

    it('throws instead of misbehaving on random garbage', () => {
      expect(() => decodeCertificate(Utils.toBase64(new Array(64).fill(0xff)))).toThrow()
      expect(() => decodeCertificate(new Uint8Array([1, 0xfd, 0xff, 0xff]))).toThrow()
    })
  })
})
