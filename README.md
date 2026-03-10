# React Native AES

AES encryption/decryption native module for React Native.

> **Note:** Version 4.x requires React Native 0.75 or higher. If you need to support
> earlier versions of React Native, please use version 3.x of this library.

## Installation

```sh
npm install react-native-aes-crypto
```

### iOS (CocoaPods)

```sh
cd ios && pod install
```

### iOS (Swift Package Manager)

In Xcode, go to **File → Add Package Dependencies** and enter the repository URL.
Or add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/tectiv3/react-native-aes.git", from: "4.0.0")
]
```

> **Note:** SPM support requires that React Native headers are available in your build
> environment. For most React Native projects, CocoaPods autolinking is still the
> standard integration method.

### Android

Linking is automatic via autolinking.

## Usage

```typescript
import { encrypt, decrypt, pbkdf2, hmac256, randomKey } from 'react-native-aes-crypto'

const generateKey = (password: string, salt: string) =>
    pbkdf2(password, salt, 100000, 256, 'sha256')

const encryptData = async (text: string, key: string) => {
    const iv = await randomKey(16)
    const cipher = await encrypt(text, key, iv, 'aes-256-cbc')
    return { cipher, iv }
}

const decryptData = (encryptedData: { cipher: string; iv: string }, key: string) =>
    decrypt(encryptedData.cipher, key, encryptedData.iv, 'aes-256-cbc')

try {
    const key = await generateKey('Arnold', 'salt')
    console.log('Key:', key)

    const encrypted = await encryptData('These violent delights have violent ends', key)
    console.log('Encrypted:', encrypted.cipher)

    const text = await decryptData(encrypted, key)
    console.log('Decrypted:', text)

    const hash = await hmac256(encrypted.cipher, key)
    console.log('HMAC:', hash)
} catch (e) {
    console.error(e)
}
```

### AES-GCM (Authenticated Encryption)

```typescript
import { encryptGcm, decryptGcm, randomKey } from 'react-native-aes-crypto'

const key = await randomKey(32) // 256-bit key
const iv = await randomKey(12) // 12-byte IV required for GCM

const cipher = await encryptGcm('sensitive data', key, iv, 'optional-aad')
const plaintext = await decryptGcm(cipher, key, iv, 'optional-aad')
```

## API Reference

### Encryption

- **`encrypt(data, key, iv, algorithm)`** — Encrypt plaintext. Returns base64.
- **`decrypt(ciphertext, key, iv, algorithm)`** — Decrypt base64 ciphertext. Returns plaintext.

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` / `ciphertext` | `string` | Plaintext or base64-encoded ciphertext |
| `key` | `string` | Hex-encoded key (16, 24, or 32 bytes) |
| `iv` | `string` | Hex-encoded IV (16 bytes) |
| `algorithm` | `AesAlgorithm` | `aes-128-cbc`, `aes-192-cbc`, `aes-256-cbc`, `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr` |

### Key Derivation

- **`pbkdf2(password, salt, cost, length, algorithm)`** — Derive a key. Returns hex.

| Parameter | Type | Description |
|-----------|------|-------------|
| `password` | `string` | Password to derive from |
| `salt` | `string` | Salt string |
| `cost` | `number` | Iteration count (min 100,000 recommended) |
| `length` | `number` | Key length **in bits** (e.g., 256 for 32-byte key) |
| `algorithm` | `PbkdfAlgorithm` | `sha1`, `sha256`, `sha512` |

### Hashing & HMAC

- **`hmac256(data, key)`** — HMAC-SHA256. Key is hex-encoded. Returns hex.
- **`hmac512(data, key)`** — HMAC-SHA512. Key is hex-encoded. Returns hex.
- **`sha256(text)`** — SHA-256 hash. Returns hex.
- **`sha512(text)`** — SHA-512 hash. Returns hex.
- **~~`sha1(text)`~~** — Deprecated. Use `sha256` or `sha512`.

### Utilities

- **`randomKey(length)`** — Generate `length` random bytes. Returns hex.
- **`randomUuid()`** — Generate a random UUID v4.

## Security Guidance

- **Always use a random IV** — generate with `randomKey(16)` for CBC/CTR, `randomKey(12)` for GCM
- **Never reuse an IV** with the same key
- **GCM requires exactly 12-byte IV** (NIST SP 800-38D)
- **Use sufficient PBKDF2 iterations** — minimum 100,000 for SHA-256, 210,000+ recommended (OWASP 2023)
- **Prefer AES-256-CBC** with HMAC verification, or use GCM for authenticated encryption
- **The `length` parameter in `pbkdf2` is in bits** — use 256 for a 32-byte key
- **`sha1` is deprecated** — use `sha256` or `sha512` instead

## Migrating from v3

- **Minimum RN 0.75**, iOS 13.0, Android API 23
- **IV is now required** — passing null/empty IV throws an error (v3 silently used zeros)
- **`pbkdf2Sync` removed** — use the async `pbkdf2` instead
- **CTR output is now base64** — v3 returned hex for CTR, base64 for CBC. v4 uses base64 for both.
  To decrypt v3 CTR data with v4, convert first: `Buffer.from(hexCiphertext, 'hex').toString('base64')`
- **Named exports** — `import { encrypt, decrypt } from 'react-native-aes-crypto'` (default export still works)
- **Strict algorithm validation** — unknown algorithm strings now throw instead of falling back

## License

MIT
