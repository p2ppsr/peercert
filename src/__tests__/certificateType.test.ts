import { describe, it, expect } from '@jest/globals'
import { Utils } from '@bsv/sdk'
import { assertCertificateType } from '../certificateType'
import { PeerCert } from '../PeerCert'

describe('certificate type boundaries', () => {
  it('accepts an unchanged canonical 32-byte identifier', () => {
    expect(() => assertCertificateType(Utils.toBase64(Array(32).fill(7)))).not.toThrow()
  })
  it.each([0, 1, 31, 33])('rejects %i decoded bytes', length => {
    expect(() => assertCertificateType(Utils.toBase64(Array(length).fill(7)))).toThrow('exactly 32 bytes')
  })
  it.each([null, undefined, 32, ' '.repeat(44), 'A'.repeat(43), 'A'.repeat(42) + 'B=', '_'.repeat(43) + '='])('rejects noncanonical encoding %s', value => {
    expect(() => assertCertificateType(value)).toThrow('canonical base64')
  })
  it('rejects empty schema names', () => {
    expect(() => PeerCert.certificateTypeFromName('  ')).toThrow('non-empty')
  })
})
