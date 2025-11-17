# peercert

**Peer-to-peer certificate issuance and management.**

PeerCert provides a clean API for issuing, receiving, and publicly revealing peer-to-peer certificates on the BSV blockchain. Built on top of `@bsv/sdk`, it simplifies complex certificate workflows into simple method calls.

## Features

- ✅ **Direct Certificate Issuance** - Issue certificates directly from one peer to another
- ✅ **Integrated MessageBox Delivery** - Send certificates automatically via MessageBox
- ✅ **Multiple Delivery Methods** - Supports MessageBox, QR codes, NFC, files, and custom channels
- ✅ **Selective Disclosure** - Create verifiable certificates revealing only selected fields
- ✅ **Automatic Verification** - Verify shared certificates with optional automatic revocation checking
- ✅ **Certificate Revocation** - Revoke certificates you issued via DID tokens on BSV overlay
- ✅ **Revocation Checking** - Check if certificates have been revoked
- ✅ **Public Reveal** - Broadcast certificates to BSV overlay for public verification
- ✅ **No Server Required** - Eliminates the need for a central certifier server
- ✅ **Cryptographic Verification** - Full signature verification using BSV identity keys
- ✅ **TypeScript Support** - Full type safety and IntelliSense support

## Installation

```bash
npm install peercert
```

## Quick Start

### Auto-Send via MessageBox (Simplest)

```typescript
import { Utils } from '@bsv/sdk'
import { PeerCert } from 'peercert'

const peercert = new PeerCert()

// Issue and automatically send via MessageBox
await peercert.issue({
  certificateType: Utils.toBase64(Utils.toArray('employment', 'utf8')),
  subjectIdentityKey: '03abc123...', // Peer's identity key
  fields: {
    role: 'Engineer',
    company: 'ACME Corp',
    start_date: '2024-01-15'
  },
  autoSend: true // Automatically sends via MessageBoxClient!
})
```

### Manual Sending (More Control)

```typescript
// Issue the certificate
const masterCert = await peercert.issue({
  certificateType: Utils.toBase64(Utils.toArray('employment', 'utf8')),
  subjectIdentityKey: '03abc123...',
  fields: { role: 'Engineer', company: 'ACME Corp' }
})

// Send via MessageBox manually
await peercert.send({
  recipient: '03abc123...',
  serializedCertificate: JSON.stringify(masterCert)
})

// Or send via other methods (QR code, NFC, file, etc.)
const serialized = JSON.stringify(masterCert)
// Display as QR, write to NFC, save to file, etc.
```

### Custom Wallet (Optional)

If you need to use a custom wallet instance:

```typescript
import { WalletClient } from '@bsv/sdk'
import { PeerCert } from 'peercert'

const customWallet = new WalletClient()
const peercert = new PeerCert(customWallet)
```

### Receiving Certificates

**From MessageBox (Recommended):**

```typescript
// Get incoming certificates from your MessageBox
const incoming = await peercert.listIncomingCertificates()

for (const cert of incoming) {
  console.log(`Certificate from ${cert.sender}`)
  
  // Receive and store the certificate
  const result = await peercert.receive(cert.serializedCertificate)
  
  if (result.success) {
    console.log('Certificate accepted!')
    // Acknowledge to remove from MessageBox
    await peercert.acknowledgeCertificate(cert.messageId)
  }
}
```

**Live Listening:**

```typescript
// Listen for certificates in real-time
await peercert.listenForCertificates(async (serializedCertificate, messageId, sender) => {
  console.log(`New certificate from ${sender}!`)
  
  const result = await peercert.receive(serializedCertificate)
  if (result.success) {
    await peercert.acknowledgeCertificate(messageId)
  }
})
```

**From Other Sources (QR, NFC, File, etc.):**

```typescript
// Receive from string
const result = await peercert.receive(serializedCertString)

// Or receive from MasterCertificate object
const result = await peercert.receive(masterCertObject)

if (result.success) {
  console.log('Certificate accepted!')
  console.log('Certificate:', result.walletCertificate)
} else {
  console.error('Failed to receive certificate:', result.error)
}
```

### Publicly Revealing Certificate Attributes

After receiving a certificate, you can publicly reveal selected attributes to the BSV overlay network:

```typescript
// Get your wallet certificate from storage
const certs = await wallet.listCertificates({
  certifiers: [issuerPublicKey],
  types: [certificateType]
})

// Publicly reveal only selected fields
const broadcastResult = await peercert.reveal({
  certificate: certs.certificates[0],
  fieldsToReveal: ['role', 'company'] // Only these fields go public
})

console.log('Certificate revealed on overlay:', broadcastResult.txid)
// Anyone can now verify these fields without contacting the certifier
```

### Verifiable Certificates (Selective Disclosure)

Create certificates that reveal only specific fields to a verifier:

```typescript
// You have a certificate in your wallet
const certs = await wallet.listCertificates({
  certifiersRequired: ['all'], // Get certificates with keyring
  limit: 1
})

// Create a verifiable certificate revealing only some fields
const verifiableCert = await peercert.createVerifiableCertificate({
  certificate: certs.certificates[0],
  verifierPublicKey: '03verifier...',
  fieldsToReveal: ['role', 'company'] // Only these fields revealed
})

// Send to verifier via MessageBox
await peercert.send({
  recipient: '03verifier...',
  serializedCertificate: JSON.stringify(verifiableCert),
  issuance: false // This is for inspection, not storage
})
```

**Verifying Shared Certificates:**

```typescript
// Receive and verify shared certificates
const incoming = await peercert.listIncomingCertificates()

for (const cert of incoming) {
  // Verify with automatic revocation check
  const result = await peercert.verifyVerifiableCertificate(
    cert.serializedCertificate,
    { checkRevocation: true }
  )
  
  if (result.verified) {
    if (result.revocationStatus?.isRevoked) {
      console.log('⚠️  Certificate has been revoked!')
    } else {
      console.log('✅ Certificate is valid')
      console.log('Revealed fields:', result.fields)
    }
  }
}
```

### Certificate Revocation

**Revoking Certificates You Issued:**

```typescript
// Get a certificate you issued
const issuedCerts = await wallet.listCertificates({
  limit: 1
})

// Revoke it
const result = await peercert.revoke(issuedCerts.certificates[0])

if (result.success) {
  console.log('Certificate revoked! TXID:', result.txid)
} else {
  console.error('Revocation failed:', result.error)
}
```

**Checking Revocation Status:**

```typescript
// Check if any certificate has been revoked
const status = await peercert.checkRevocation(certificate)

if (status.isRevoked) {
  console.log('⚠️  Certificate has been revoked')
  console.log(status.message)
} else {
  console.log('✅ Certificate is still valid')
}
```

## Use Cases

### Trust Networks
Build decentralized reputation systems where peers vouch for each other:
```typescript
await peercert.issue({
  certificateType: Utils.toBase64(Utils.toArray('reputation', 'utf8')),
  subjectIdentityKey: peerKey,
  fields: {
    rating: '5',
    completed_transactions: '47',
    endorsed_skills: 'JavaScript,TypeScript,React'
  }
})
```

### Identity Verification
Peers can verify each other's identity attributes:
```typescript
await peercert.issue({
  certificateType: Utils.toBase64(Utils.toArray('identity-verification', 'utf8')),
  subjectIdentityKey: peerKey,
  fields: {
    verified_name: 'true',
    verified_email: 'true',
    verified_date: '2024-01-15'
  }
})
```

### Skill Endorsements
Create professional endorsements without centralized platforms:
```typescript
await peercert.issue({
  certificateType: Utils.toBase64(Utils.toArray('skill-endorsement', 'utf8')),
  subjectIdentityKey: peerKey,
  fields: {
    skill: 'Smart Contract Development',
    level: 'expert',
    years_known: '3'
  }
})
```

## How It Works

### Traditional Certificate Model
In the traditional model, you need a server:
```
Client → acquireCertificate(acquisitionProtocol: 'issuance', certifierUrl: '...') → Server
```
The server verifies attributes and signs the certificate.

### PeerCert Model
With PeerCert, peers directly issue certificates:
```
Peer A (Issuer) → peercert.issue() → Master Certificate → Send to Peer B
Peer B (Recipient) → peercert.receive() → Verifies & Stores Certificate
Peer B (Optional) → peercert.reveal() → Broadcasts to BSV Overlay
```

**Under the hood:**
1. **Issuer** creates a `MasterCertificate` with encrypted fields
2. **Issuer** signs the certificate with their identity key  
3. **Issuer** creates a DID revocation outpoint on-chain (tagged with serial number)
4. **Recipient** receives and verifies the signature
5. **Recipient** stores the certificate in their wallet using `acquireCertificate()`
6. **Recipient** can:
   - Publicly reveal selected fields to the overlay network
   - Create verifiable certificates revealing only selected fields to specific verifiers
   - Check revocation status via DID overlay queries
7. **Issuer** can revoke issued certificates by spending the DID token

## API Reference

### `new PeerCert(wallet?, options?)`

Create a new PeerCert instance.

**Parameters:**
- `wallet?: WalletInterface` - Optional wallet to use for operations (defaults to `new WalletClient()`)
- `options?: PeerCertOptions` - Optional configuration
  - `originator?: string` - Originator domain for wallet operations
  - `networkPreset?: 'mainnet' | 'testnet' | 'local'` - Network configuration for DID operations
  - `messageBoxHost?: string` - MessageBox server URL (defaults to 'https://messagebox.babbage.systems')
  - `enableMessageBoxLogging?: boolean` - Enable logging for MessageBox operations

**Returns:** `PeerCert` instance

**Example:**
```typescript
// Simple usage with default wallet
const peercert = new PeerCert()

// With custom wallet
const peercert = new PeerCert(myWallet)

// With options
const peercert = new PeerCert(myWallet, { 
  originator: 'myapp.com',
  networkPreset: 'mainnet'
})
```

### `peercert.issue(options)`

Issue a certificate to a peer.

**Parameters:** `IssueOptions`
- `certificateType: string` - Certificate type identifier (base64 encoded)
- `subjectIdentityKey: string` - The peer's identity public key
- `fields: Record<string, string>` - Certificate fields to attest
- `autoSend?: boolean` - Automatically send via MessageBox (defaults to false)

**Returns:** `Promise<MasterCertificate>` - The created certificate

### `peercert.receive(certificate)`

Receive and verify a certificate from a peer.

**Parameters:**
- `certificate: string | MasterCertificate` - Serialized certificate JSON or MasterCertificate object

**Returns:** `Promise<ReceiveResult>`
- `success: boolean` - Whether the operation succeeded
- `walletCertificate?: WalletCertificate` - The stored certificate
- `error?: string` - Error message if failed

### `peercert.reveal(options)`

Publicly reveal selected certificate fields to the BSV overlay network.

**Parameters:** `RevealOptions`
- `certificate: WalletCertificate` - Certificate from your wallet
- `fieldsToReveal: CertificateFieldNameUnder50Bytes[]` - Fields to reveal publicly

**Returns:** `Promise<RevealResult>` - Broadcast response from overlay network (BroadcastResponse | BroadcastFailure)

### `peercert.send(options)`

Send a certificate to a recipient via MessageBox.

**Parameters:** `SendOptions`
- `recipient: string` - Recipient's identity public key
- `serializedCertificate: string` - Serialized certificate JSON
- `issuance?: boolean` - Whether this is an issuance (true, default) or sharing for inspection (false)

**Returns:** `Promise<void>`

### `peercert.listIncomingCertificates()`

List incoming certificates from your MessageBox.

**Returns:** `Promise<PendingCertificate[]>` - Array of incoming certificates

**PendingCertificate Type:**
- `serializedCertificate: string` - Serialized certificate JSON
- `messageId: string` - MessageBox message ID for acknowledgment
- `sender: string` - Sender's identity public key

### `peercert.acknowledgeCertificate(messageId)`

Acknowledge a certificate message in MessageBox (marks it as read/processed).

**Parameters:**
- `messageId: string` - The message ID to acknowledge

**Returns:** `Promise<void>`

### `peercert.listenForCertificates(callback)`

Listen for live certificate messages from MessageBox.

**Parameters:**
- `callback: (serializedCertificate: string, messageId: string, sender: string, issuance: boolean) => void | Promise<void>`
  - `serializedCertificate` - The certificate JSON
  - `messageId` - MessageBox message ID
  - `sender` - Sender's public key
  - `issuance` - Whether this is an issuance (true) or shared for inspection (false)

**Returns:** `Promise<void>` - Starts listening (call is async but keeps connection open)

### `peercert.createVerifiableCertificate(options)`

Create a verifiable certificate that reveals only selected fields to a verifier.

**Parameters:** `CreateVerifiableCertificateOptions`
- `certificate: WalletCertificate` - Certificate from your wallet (must have keyring - use `certifiersRequired: ['all']` when listing)
- `verifierPublicKey: string` - Public key of who will verify the certificate
- `fieldsToReveal: string[]` - Which fields to reveal (other fields remain encrypted)

**Returns:** `Promise<VerifiableCertificate>` - Verifiable certificate with selective field revelation

**Example:**
```typescript
const certs = await wallet.listCertificates({
  certifiers: ['certifierIdentityKey'], // Required to get keyring
  limit: 1
})

const verifiable = await peercert.createVerifiableCertificate({
  certificate: certs.certificates[0],
  verifierPublicKey: '03verifier...',
  fieldsToReveal: ['role', 'company']
})
```

### `peercert.verifyVerifiableCertificate(serializedCertificate, options?)`

Verify and decrypt a verifiable certificate shared with you.

**Parameters:**
- `serializedCertificate: string` - Serialized verifiable certificate JSON
- `options?: VerifyVerifiableCertificateOptions`
  - `checkRevocation?: boolean` - Automatically check if certificate has been revoked (default: false)

**Returns:** `Promise<VerifyVerifiableCertificateResult>`
- `verified: boolean` - Whether verification succeeded
- `fields?: Record<string, string>` - Decrypted revealed fields
- `revocationStatus?: RevocationStatus` - Revocation status if checkRevocation was enabled
- `error?: string` - Error message if verification failed

**Example:**
```typescript
const result = await peercert.verifyVerifiableCertificate(certString, {
  checkRevocation: true
})

if (result.verified && !result.revocationStatus?.isRevoked) {
  console.log('Valid certificate:', result.fields)
}
```

### `peercert.checkRevocation(certificate)`

Check if a certificate has been revoked.

**Parameters:**
- `certificate: WalletCertificate` - Certificate to check

**Returns:** `Promise<RevocationStatus>`
- `isRevoked: boolean` - Whether the certificate has been revoked
- `revocationOutpoint: string` - The revocation outpoint that was checked
- `message?: string` - Additional details about revocation status

**Example:**
```typescript
const status = await peercert.checkRevocation(myCertificate)

if (status.isRevoked) {
  console.log('Certificate has been revoked')
}
```

### `peercert.revoke(certificate)`

Revoke a certificate that you issued.

**Parameters:**
- `certificate: WalletCertificate` - Certificate you issued (that you want to revoke)

**Returns:** `Promise<RevokeResult>`
- `success: boolean` - Whether revocation succeeded
- `txid?: string` - Transaction ID of the revocation
- `revocationOutpoint?: string` - The revocation outpoint that was spent
- `error?: string` - Error message if revocation failed

**Example:**
```typescript
const result = await peercert.revoke(issuedCertificate)

if (result.success) {
  console.log('Certificate revoked! TXID:', result.txid)
}
```

## Complete Example

Here's a complete workflow showing certificate issuance, receipt, and public reveal:

```typescript
import { Utils } from '@bsv/sdk'
import { PeerCert } from 'peercert'

// Step 1: Alice issues a certificate to Bob
const alicePeercert = new PeerCert()
const bobPublicKey = '02bob...'

const masterCert = await alicePeercert.issue({
  certificateType: Utils.toBase64(Utils.toArray('professional-endorsement', 'utf8')),
  subjectIdentityKey: bobPublicKey,
  fields: {
    skill: 'TypeScript Development',
    level: 'expert',
    projects_completed: '15',
    years_known: '2'
  }
})

// Alice sends the certificate to Bob (JSON.stringify(masterCert))
const serialized = JSON.stringify(masterCert)

// Step 2: Bob receives and verifies Alice's certificate
const bobPeercert = new PeerCert()

const result = await bobPeercert.receive(serialized)

if (!result.success) {
  throw new Error('Certificate verification failed: ' + result.error)
}

console.log('Certificate received and stored!')
console.log('Certifier:', result.walletCertificate?.certifier)

// Step 3: Bob publicly reveals some fields on the overlay network
// First get the certificate from Bob's wallet
const bobWallet = bobPeercert['wallet'] // Access internal wallet
const certs = await bobWallet.listCertificates({
  certifiers: [alicePublicKey],
  types: [Utils.toBase64(Utils.toArray('professional-endorsement', 'utf8'))]
})

const broadcastResult = await bobPeercert.reveal({
  certificate: certs.certificates[0],
  fieldsToReveal: ['skill', 'level'] // Only these fields go public
})

console.log('Certificate revealed:', broadcastResult.txid)
// Anyone can now verify Bob's skill and level without contacting Alice
// projects_completed and years_known remain private
```

## Security Considerations

1. **Signature Verification**: The `receive()` and `verifyVerifiableCertificate()` methods automatically verify certificate signatures
2. **Trust Model**: Certificates represent the issuer's attestation - trust is based on knowing and trusting the issuer
3. **Selective Disclosure**: 
   - Use `reveal()` to share only necessary fields publicly on the overlay network
   - Use `createVerifiableCertificate()` to share selected fields privately with a specific verifier
4. **Revocation**: 
   - All certificates include DID-based revocation outpoints on the BSV blockchain
   - Use `checkRevocation()` to manually verify revocation status
   - Use `verifyVerifiableCertificate()` with `checkRevocation: true` for automatic checking
   - Issuers can revoke certificates they issued using `revoke()`
5. **Private Keys**: Never share your wallet's private keys - certificates use identity-based encryption
6. **Verifiable Certificates**: When creating verifiable certificates, only specified fields are decryptable by the verifier

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build the package
npm run build

# This creates:
# - dist/cjs/ - CommonJS build
# - dist/esm/ - ES modules build  
# - dist/types/ - TypeScript declarations
```

## License

Open BSV License

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/p2ppsr/peercert)
