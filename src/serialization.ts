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
 * Encode a MasterCertificate to compact binary format
 * @param cert - The certificate to encode
 * @param outputFormat - 'binary' (default) or 'base64'
 * @returns Binary data as Uint8Array or base64 string
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
  const [txidHex, voutStr] = cert.revocationOutpoint.split('.')
  const txidBytes = Utils.toArray(txidHex, 'hex').reverse() // Little-endian
  if (txidBytes.length !== 32) {
    throw new Error('Revocation txid must be 32 bytes')
  }
  writer.write(txidBytes)

  const vout = parseInt(voutStr, 10)
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
    const keyBytes = Utils.toArray(cert.masterKeyring[fieldName], 'base64')
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
 * @param encoded - Binary data (Uint8Array) or base64 string
 * @param inputFormat - 'binary' (default) or 'base64'
 * @returns Decoded certificate data
 */
export function decodeCertificate(encoded: Uint8Array | string, inputFormat: 'binary' | 'base64' = 'binary'): {
  type: string
  serialNumber: string
  subject: string
  certifier: string
  revocationOutpoint: string
  fields: Record<string, string>
  masterKeyring: Record<string, string>
  signature: string
} {
  // Convert to binary array if needed
  let binary: number[]
  if (inputFormat === 'base64') {
    binary = Utils.toArray(encoded as string, 'base64')
  } else {
    binary = encoded instanceof Uint8Array ? Array.from(encoded) : encoded as unknown as number[]
  }

  const reader = new Utils.Reader(binary)

  // Version
  const version = reader.read(1)[0]
  if (version !== VERSION) {
    throw new Error(`Unsupported certificate format version: ${version}`)
  }

  // Type
  const typeLen = reader.readVarIntNum()
  const typeBytes = reader.read(typeLen)
  const type = Utils.toBase64(typeBytes)

  // Serial number (32 bytes fixed)
  const serialBytes = reader.read(32)
  const serialNumber = Utils.toBase64(serialBytes)

  // Subject pubkey (33 bytes fixed)
  const subjectBytes = reader.read(33)
  const subject = Utils.toHex(subjectBytes)

  // Certifier pubkey (33 bytes fixed)
  const certifierBytes = reader.read(33)
  const certifier = Utils.toHex(certifierBytes)

  // Revocation outpoint
  const txidBytes = reader.read(32).reverse() // Back to big-endian
  const txid = Utils.toHex(txidBytes)
  const vout = reader.readVarIntNum()
  const revocationOutpoint = `${txid}.${vout}`

  // Signature
  const sigLen = reader.readVarIntNum()
  const sigBytes = reader.read(sigLen)
  const signature = Utils.toHex(sigBytes)

  // Fields
  const fieldCount = reader.readVarIntNum()
  const fields: Record<string, string> = {}
  const masterKeyring: Record<string, string> = {}

  for (let i = 0; i < fieldCount; i++) {
    // Field name
    const nameLen = reader.readVarIntNum()
    const nameBytes = reader.read(nameLen)
    const fieldName = Utils.toUTF8(nameBytes)

    // Encrypted value
    const valueLen = reader.readVarIntNum()
    const valueBytes = reader.read(valueLen)
    fields[fieldName] = Utils.toBase64(valueBytes)

    // Master key
    const keyLen = reader.readVarIntNum()
    const keyBytes = reader.read(keyLen)
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
