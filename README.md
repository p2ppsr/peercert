# peercert

**Peer-to-peer certificate issuance and management.**

PeerCert provides a clean API for issuing, receiving, and publicly revealing peer-to-peer certificates on the BSV blockchain. Built on top of `@bsv/sdk`, it simplifies complex certificate workflows into simple method calls.

## Features

- ✅ **Direct Certificate Issuance** - Issue certificates directly from one peer to another
- ✅ **Integrated MessageBox Delivery** - Send certificates automatically via MessageBox
- ✅ **Multiple Delivery Methods** - Supports MessageBox, QR codes, NFC, files, and custom channels
- ✅ **No Server Required** - Eliminates the need for a central certifier server
- ✅ **Selective Disclosure** - Reveal only selected certificate fields publicly
- ✅ **Public Reveal** - Broadcast certificates to BSV overlay for public verification
- ✅ **Cryptographic Verification** - Full signature verification using BSV identity keys
- ✅ **TypeScript Support** - Full type safety and IntelliSense support
- ✅ **Certificate Revocation** - Revocation via DID tokens on BSV overlay network

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
  subjectPublicKey: '03abc123...', // Peer's identity key
  fields: {
    role: 'Engineer',
    company: 'ACME Corp',
    start_date: '2024-01-15'
  },
  autoSend: true // Automatically sends via MessageBox!
})
```

### Manual Sending (More Control)

```typescript
// Issue the certificate
const masterCert = await peercert.issue({
  certificateType: Utils.toBase64(Utils.toArray('employment', 'utf8')),
  subjectPublicKey: '03abc123...',
  fields: { role: 'Engineer', company: 'ACME Corp' }
})

// Send via MessageBox manually
await peercert.send({
  recipient: '03abc123...',
  certificateType: Utils.toBase64(Utils.toArray('employment', 'utf8')),
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

## Use Cases

### Trust Networks
Build decentralized reputation systems where peers vouch for each other:
```typescript
await peercert.issue({
  certificateType: Utils.toBase64(Utils.toArray('reputation', 'utf8')),
  subjectPublicKey: peerKey,
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
  subjectPublicKey: peerKey,
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
  subjectPublicKey: peerKey,
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
3. **Issuer** creates a DID revocation outpoint on-chain
4. **Recipient** receives and verifies the signature
5. **Recipient** stores the certificate in their wallet using `acquireCertificate()`
6. **Recipient** can publicly reveal selected fields to the overlay network

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
- `subjectPublicKey: string` - The peer's identity public key
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
- `certificateType: string` - Certificate type identifier
- `serializedCertificate: string` - Serialized certificate JSON

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
- `callback: (serializedCertificate: string, messageId: string, sender: string) => void | Promise<void>`

**Returns:** `Promise<void>` - Starts listening (call is async but keeps connection open)

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
  subjectPublicKey: bobPublicKey,
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

1. **Signature Verification**: The `receive()` method automatically verifies certificate signatures
2. **Trust Model**: Certificates represent the issuer's attestation - trust is based on knowing and trusting the issuer
3. **Selective Disclosure**: Use `reveal()` to share only necessary fields publicly on the overlay network
4. **Revocation**: Certificates include DID-based revocation outpoints on the BSV blockchain
5. **Private Keys**: Never share your wallet's private keys - certificates use identity-based encryption

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

PROPRIETARY

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/p2ppsr/peercert)
