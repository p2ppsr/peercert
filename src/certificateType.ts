import { Utils } from '@bsv/sdk'

/** Require canonical standard base64 encoding of exactly 32 bytes. */
export function assertCertificateType(type: unknown): asserts type is string {
  if (typeof type !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(type) ||
      Utils.toBase64(Utils.toArray(type, 'base64')) !== type) {
    throw new Error('Certificate type must be canonical base64 encoding of exactly 32 bytes. Use PeerCert.certificateTypeFromName(name) for a new human-readable schema name; existing signed types must not be rewritten.')
  }
}
