import { Utils } from '@bsv/sdk'
import type { MasterCertificate } from '@bsv/sdk'

/**
 * Compact binary format for certificates using Utils.Writer/Reader
 *
 * Format version 1:
 * - Version (1 byte): 0x01
 * - Type length (VarInt) + type data (base64 decoded to bytes)
 * - Serial number (32 bytes fixed)
 * - Subject pubkey (33 bytes fixed)
 * - Certifier pubkey (33 bytes fixed)
 * - Revocation outpoint txid (32 bytes fixed, little-endian)
 * - Revocation outpoint vout (VarInt)
 * - Signature length (VarInt) + signature (hex decoded to bytes)
 * - Field count (VarInt)
 * - For each field:
 *   - Name length (VarInt) + name (UTF-8)
 *   - Encrypted value length (VarInt) + value (base64 decoded)
 *   - Master key length (VarInt) + key (base64 decoded)
 */

const VERSION = 1

/**
 * Upper bound on the number of fields a decoded certificate may declare.
 * Prevents maliciously crafted input (e.g. from a QR code or URL) from
 * driving an unbounded decode loop.
 */
const MAX_FIELDS = 256

/**
 * Decoded certificate data, suitable for reconstructing a MasterCertificate
 * or passing directly to PeerCert.receive()
 */
export interface DecodedCertificate {
  type: string
  serialNumber: string
  subject: string
  certifier: string
  revocationOutpoint: string
  fields: Record<string, string>
  masterKeyring: Record<string, string>
  signature: string
}

/**
 * Encode a MasterCertificate to compact binary format
 * @param cert - The certificate to encode
 * @param outputFormat - 'base64' (default) or 'binary'
 * @returns Base64 string or binary data as Uint8Array
 */
export function encodeCertificate(cert: MasterCertificate, outputFormat: 'binary' | 'base64' = 'base64'): Uint8Array | string {
  const writer = new Utils.Writer()

  // Version
  writer.write([VERSION])

  // Type (base64 string -> bytes)
  const typeBytes = Utils.toArray(cert.type, 'base64')
  writer.writeVarIntNum(typeBytes.length)
  writer.write(typeBytes)

  // Serial number (32 bytes fixed)
  const serialBytes = Utils.toArray(cert.serialNumber, 'base64')
  if (serialBytes.length !== 32) {
    throw new Error('Serial number must be 32 bytes')
  }
  writer.write(serialBytes)

  // Subject pubkey (33 bytes fixed, compressed)
  const subjectBytes = Utils.toArray(cert.subject, 'hex')
  if (subjectBytes.length !== 33) {
    throw new Error('Subject pubkey must be 33 bytes (compressed)')
  }
  writer.write(subjectBytes)

  // Certifier pubkey (33 bytes fixed, compressed)
  const certifierBytes = Utils.toArray(cert.certifier, 'hex')
  if (certifierBytes.length !== 33) {
    throw new Error('Certifier pubkey must be 33 bytes (compressed)')
  }
  writer.write(certifierBytes)

  // Revocation outpoint: parse "txid.vout" format
  const outpointParts = cert.revocationOutpoint?.split('.') ?? []
  if (outpointParts.length !== 2) {
    throw new Error('Revocation outpoint must be in "txid.vout" format')
  }
  const [txidHex, voutStr] = outpointParts
  const txidBytes = Utils.toArray(txidHex, 'hex').reverse() // Little-endian
  if (txidBytes.length !== 32) {
    throw new Error('Revocation txid must be 32 bytes')
  }
  writer.write(txidBytes)

  const vout = parseInt(voutStr, 10)
  if (!Number.isInteger(vout) || vout < 0 || String(vout) !== voutStr) {
    throw new Error('Revocation outpoint vout must be a non-negative integer')
  }
  writer.writeVarIntNum(vout)

  // Signature
  if (!cert.signature) {
    throw new Error('Certificate must have a signature')
  }
  const sigBytes = Utils.toArray(cert.signature, 'hex')
  writer.writeVarIntNum(sigBytes.length)
  writer.write(sigBytes)

  // Fields
  const fieldNames = Object.keys(cert.fields)
  writer.writeVarIntNum(fieldNames.length)

  for (const fieldName of fieldNames) {
    // Field name (UTF-8)
    const nameBytes = Utils.toArray(fieldName, 'utf8')
    writer.writeVarIntNum(nameBytes.length)
    writer.write(nameBytes)

    // Encrypted field value (base64 -> bytes)
    const valueBytes = Utils.toArray(cert.fields[fieldName], 'base64')
    writer.writeVarIntNum(valueBytes.length)
    writer.write(valueBytes)

    // Master keyring value (base64 -> bytes)
    const keyringEntry = cert.masterKeyring?.[fieldName]
    if (!keyringEntry) {
      throw new Error(`Missing master keyring entry for field "${fieldName}"`)
    }
    const keyBytes = Utils.toArray(keyringEntry, 'base64')
    writer.writeVarIntNum(keyBytes.length)
    writer.write(keyBytes)
  }

  // Return binary by default, or base64 if requested
  const binary = writer.toArray()
  if (outputFormat === 'base64') {
    return Utils.toBase64(binary)
  }
  return new Uint8Array(binary)
}

/**
 * Decode a compact binary certificate back to MasterCertificate data
 *
 * The input format is detected from the input type: strings are treated as
 * base64, byte arrays (Uint8Array or number[]) as raw binary.
 *
 * Decoding is safe against untrusted input (QR codes, URLs, NFC): all declared
 * lengths are validated against the remaining data before any read, and the
 * field count is capped, so malformed or malicious payloads throw a clear
 * error instead of producing garbage or looping.
 *
 * @param encoded - Base64 string, Uint8Array, or number[] of binary data
 * @param inputFormat - Deprecated: format is now inferred from the input type
 * @returns Decoded certificate data
 */
export function decodeCertificate(encoded: Uint8Array | number[] | string, inputFormat?: 'binary' | 'base64'): DecodedCertificate {
  // Format is inferred from the runtime type; the inputFormat parameter is
  // retained for backward compatibility but no longer trusted (previous
  // versions had conflicting defaults that could misinterpret input).
  let binary: number[]
  if (typeof encoded === 'string') {
    binary = Utils.toArray(encoded, 'base64')
  } else {
    binary = Array.from(encoded)
  }

  const reader = new Utils.Reader(binary)

  // Utils.Reader silently returns short arrays on over-read, so every
  // declared length must be validated against the remaining bytes first.
  const remaining = (): number => binary.length - reader.pos
  const readBytes = (length: number, what: string): number[] => {
    if (!Number.isInteger(length) || length < 0 || length > remaining()) {
      throw new Error(
        `Malformed certificate: ${what} length ${length} exceeds remaining data (${remaining()} bytes)`
      )
    }
    return reader.read(length)
  }
  const readVarLength = (what: string): number => {
    if (remaining() < 1) {
      throw new Error(`Malformed certificate: unexpected end of data reading ${what} length`)
    }
    return reader.readVarIntNum()
  }

  // Version
  const version = readBytes(1, 'version')[0]
  if (version !== VERSION) {
    throw new Error(`Unsupported certificate format version: ${version}`)
  }

  // Type
  const typeBytes = readBytes(readVarLength('type'), 'type')
  const type = Utils.toBase64(typeBytes)

  // Serial number (32 bytes fixed)
  const serialBytes = readBytes(32, 'serial number')
  const serialNumber = Utils.toBase64(serialBytes)

  // Subject pubkey (33 bytes fixed)
  const subjectBytes = readBytes(33, 'subject pubkey')
  const subject = Utils.toHex(subjectBytes)

  // Certifier pubkey (33 bytes fixed)
  const certifierBytes = readBytes(33, 'certifier pubkey')
  const certifier = Utils.toHex(certifierBytes)

  // Revocation outpoint
  const txidBytes = readBytes(32, 'revocation txid').reverse() // Back to big-endian
  const txid = Utils.toHex(txidBytes)
  if (remaining() < 1) {
    throw new Error('Malformed certificate: unexpected end of data reading vout')
  }
  const vout = reader.readVarIntNum()
  const revocationOutpoint = `${txid}.${vout}`

  // Signature
  const sigBytes = readBytes(readVarLength('signature'), 'signature')
  const signature = Utils.toHex(sigBytes)

  // Fields
  const fieldCount = readVarLength('field count')
  if (fieldCount > MAX_FIELDS) {
    throw new Error(`Malformed certificate: field count ${fieldCount} exceeds maximum of ${MAX_FIELDS}`)
  }
  const fields: Record<string, string> = {}
  const masterKeyring: Record<string, string> = {}

  for (let i = 0; i < fieldCount; i++) {
    // Field name
    const nameBytes = readBytes(readVarLength('field name'), 'field name')
    const fieldName = Utils.toUTF8(nameBytes)

    // Encrypted value
    const valueBytes = readBytes(readVarLength('field value'), 'field value')
    fields[fieldName] = Utils.toBase64(valueBytes)

    // Master key
    const keyBytes = readBytes(readVarLength('field key'), 'field key')
    masterKeyring[fieldName] = Utils.toBase64(keyBytes)
  }

  return {
    type,
    serialNumber,
    subject,
    certifier,
    revocationOutpoint,
    fields,
    masterKeyring,
    signature
  }
}

/**
 * Get the estimated size in bytes of a certificate when encoded
 * Note: VarInt sizes are estimated (typically 1-3 bytes for certificate data)
 */
export function estimateEncodedSize(cert: MasterCertificate): number {
  // Helper to estimate VarInt size
  const varIntSize = (n: number): number => {
    if (n < 0xfd) return 1
    if (n <= 0xffff) return 3
    if (n <= 0xffffffff) return 5
    return 9
  }

  let size = 0

  // Fixed overhead
  size += 1 // version

  // Type (VarInt length + data)
  const typeBytes = Utils.toArray(cert.type, 'base64')
  size += varIntSize(typeBytes.length) + typeBytes.length

  size += 32 // serial number (fixed)
  size += 33 // subject pubkey (fixed)
  size += 33 // certifier pubkey (fixed)
  size += 32 // txid (fixed)

  // Vout (VarInt)
  const [, voutStr] = cert.revocationOutpoint.split('.')
  size += varIntSize(parseInt(voutStr, 10))

  // Signature (VarInt length + data)
  const sigBytes = cert.signature ? Utils.toArray(cert.signature, 'hex') : []
  size += varIntSize(sigBytes.length) + sigBytes.length

  // Field count (VarInt)
  const fieldNames = Object.keys(cert.fields)
  size += varIntSize(fieldNames.length)

  // Variable fields
  for (const fieldName of fieldNames) {
    // Name (VarInt length + UTF-8 data)
    const nameBytes = Utils.toArray(fieldName, 'utf8')
    size += varIntSize(nameBytes.length) + nameBytes.length

    // Value (VarInt length + base64-decoded data)
    const valueBytes = Utils.toArray(cert.fields[fieldName], 'base64')
    size += varIntSize(valueBytes.length) + valueBytes.length

    // Key (VarInt length + base64-decoded data)
    const keyBytes = Utils.toArray(cert.masterKeyring[fieldName], 'base64')
    size += varIntSize(keyBytes.length) + keyBytes.length
  }

  return size
}
