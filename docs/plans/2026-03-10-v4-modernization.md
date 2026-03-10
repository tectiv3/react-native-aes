# react-native-aes-crypto v4.0 Modernization Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Modernize react-native-aes-crypto from a 10-year-old legacy bridge module to a secure, TurboModule-based v4.0 with proper TypeScript, input validation, and authenticated encryption support.

**Architecture:** v4 drops the legacy bridge in favor of TurboModules (Codegen), rewrites the JS layer in TypeScript with input validation, fixes all critical crypto bugs on both platforms, adds AES-GCM, and uses react-native-builder-bob for build tooling. Minimum RN 0.75.

**Tech Stack:** TypeScript (JS layer), Objective-C with CommonCrypto (iOS), Kotlin with javax.crypto (Android), react-native-builder-bob (build), Codegen (TurboModule spec)

**Breaking changes from v3:**
- Minimum React Native 0.75
- Minimum iOS 13.0, Android API 23
- `pbkdf2Sync` removed (was blocking JS thread)
- Null/empty IV now throws instead of silently using zeros
- PBKDF2 `length` parameter now consistently means **bytes** (not bits)
- Output encoding: both CBC and CTR now return base64 (v3 CBC=base64, CTR=hex)
- Import changed: `import { encrypt, decrypt } from 'react-native-aes-crypto'` (named exports + default)
- `sha1` deprecated (still available, marked in types)

---

## Phase 1: Critical Security Fixes

These fixes go into the existing Objective-C/Java code. They are prerequisite to the architecture migration — we fix the crypto first, then restructure.

### Task 1.1: Reject Null/Empty IV

**Files:**
- Modify: `ios/Aes/lib/AesCrypt.m:76-116` (AESCBC method)
- Modify: `ios/Aes/lib/AesCrypt.m:118-188` (AESCTR method)
- Modify: `android/src/main/java/com/tectiv3/aes/Aes.java:216-244` (encrypt/decrypt)

**Step 1: Fix iOS — AESCBC**

In `AesCrypt.m`, add IV validation at the top of the `AESCBC` method (after line 79):

```objc
+ (NSData *) AESCBC: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];

    // Reject missing or wrong-length IV
    if (ivData.length != kCCBlockSizeAES128) {
        NSLog(@"AES error: IV must be exactly 16 bytes, got %lu", (unsigned long)ivData.length);
        return nil;
    }
    // ... rest of method unchanged, but remove the ternary on line 105:
    // REPLACE: ivData.length ? ivData.bytes : nil,
    // WITH:    ivData.bytes,
```

**Step 2: Fix iOS — AESCTR**

Same pattern in the `AESCTR` method. Add IV validation after line 121, replace line 149 ternary.

**Step 3: Fix Android — remove emptyIvSpec and reject null IV**

In `Aes.java`:
- Delete line 216 (`final static IvParameterSpec emptyIvSpec = ...`)
- In `encrypt()` (line 227): replace the ternary with a null check that throws
- In `decrypt()` (line 241): same

```java
private static String encrypt(String text, String hexKey, String hexIv, String algorithm) throws Exception {
    if (text == null || text.length() == 0) {
        throw new IllegalArgumentException("Data must not be null or empty");
    }
    if (hexIv == null || hexIv.length() == 0) {
        throw new IllegalArgumentException("IV must not be null or empty");
    }

    byte[] key = Hex.decode(hexKey);
    byte[] ivBytes = Hex.decode(hexIv);
    if (ivBytes.length != 16) {
        throw new IllegalArgumentException("IV must be exactly 16 bytes, got " + ivBytes.length);
    }

    SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));
    byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
    return Base64.encodeToString(encrypted, Base64.NO_WRAP);
}
```

Apply matching changes to `decrypt()`.

**Step 4: Commit**
```
git add ios/Aes/lib/AesCrypt.m android/src/main/java/com/tectiv3/aes/Aes.java
git commit -m "security: reject null/empty IV instead of falling back to zeros"
```

---

### Task 1.2: Fix CTR Padding

**Files:**
- Modify: `ios/Aes/lib/AesCrypt.m:148` (ccPKCS7Padding → ccNoPadding)
- Modify: `android/src/main/java/com/tectiv3/aes/Aes.java:47` (PKCS5Padding → NoPadding)

**Step 1: Fix iOS**

In `AesCrypt.m` line 148, change:
```objc
// FROM:
ccPKCS7Padding,
// TO:
ccNoPadding,
```

**Step 2: Fix Android**

In `Aes.java` line 47, change:
```java
// FROM:
private static final String CIPHER_CTR_ALGORITHM = "AES/CTR/PKCS5Padding";
// TO:
private static final String CIPHER_CTR_ALGORITHM = "AES/CTR/NoPadding";
```

**Step 3: Commit**
```
git add ios/Aes/lib/AesCrypt.m android/src/main/java/com/tectiv3/aes/Aes.java
git commit -m "security: fix CTR mode to use NoPadding instead of PKCS padding"
```

---

### Task 1.3: Validate Key Length Against Algorithm

**Files:**
- Modify: `ios/Aes/lib/AesCrypt.m:76-96` (AESCBC key validation)
- Modify: `ios/Aes/lib/AesCrypt.m:118-138` (AESCTR key validation)
- Modify: `android/src/main/java/com/tectiv3/aes/Aes.java:218-230` (encrypt key validation)

**Step 1: Fix iOS — add key length validation after algorithm switch**

In both `AESCBC` and `AESCTR`, after the `keyLength` switch statement, add:

```objc
    if (keyData.length != keyLength) {
        NSLog(@"AES error: key length %lu does not match algorithm requirement %zu",
              (unsigned long)keyData.length, keyLength);
        return nil;
    }
```

**Step 2: Fix Android — validate key length**

In `encrypt()` and `decrypt()`, after decoding the hex key:

```java
    byte[] key = Hex.decode(hexKey);
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        throw new IllegalArgumentException(
            "Key must be 16, 24, or 32 bytes for AES-128/192/256, got " + key.length);
    }
```

**Step 3: Commit**
```
git add ios/Aes/lib/AesCrypt.m android/src/main/java/com/tectiv3/aes/Aes.java
git commit -m "security: validate key length matches algorithm requirement"
```

---

### Task 1.4: Strict Algorithm Whitelist

**Files:**
- Modify: `ios/Aes/lib/AesCrypt.m:190-210` (encrypt/decrypt dispatch)
- Modify: `android/src/main/java/com/tectiv3/aes/Aes.java:62-78` (encrypt/decrypt ReactMethods)

**Step 1: Fix iOS — replace containsString with exact match**

Replace the `encrypt:` and `decrypt:` dispatch methods:

```objc
+ (NSString *) encrypt: (NSString *)clearText key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    NSSet *cbcAlgorithms = [NSSet setWithArray:@[@"aes-128-cbc", @"aes-192-cbc", @"aes-256-cbc"]];
    NSSet *ctrAlgorithms = [NSSet setWithArray:@[@"aes-128-ctr", @"aes-192-ctr", @"aes-256-ctr"]];

    if ([ctrAlgorithms containsObject:algorithm]) {
        NSData *result = [self AESCTR:@"encrypt" data:[clearText dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv algorithm:algorithm];
        return [result base64EncodedStringWithOptions:0];
    } else if ([cbcAlgorithms containsObject:algorithm]) {
        NSData *result = [self AESCBC:@"encrypt" data:[clearText dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv algorithm:algorithm];
        return [result base64EncodedStringWithOptions:0];
    }
    return nil;
}
```

Note: CTR now also returns base64 (was hex in v3 — breaking change for consistency).

Apply same pattern to `decrypt:`.

**Step 2: Fix Android — strict algorithm mapping**

```java
@ReactMethod
public void encrypt(String data, String key, String iv, String algorithm, Promise promise) {
    try {
        String cipherAlgorithm = mapAlgorithm(algorithm);
        String result = encrypt(data, key, iv, cipherAlgorithm);
        promise.resolve(result);
    } catch (Exception e) {
        promise.reject("ENCRYPT_ERROR", e.getMessage());
    }
}

private static String mapAlgorithm(String algorithm) {
    switch (algorithm.toLowerCase()) {
        case "aes-128-cbc":
        case "aes-192-cbc":
        case "aes-256-cbc":
            return CIPHER_CBC_ALGORITHM;
        case "aes-128-ctr":
        case "aes-192-ctr":
        case "aes-256-ctr":
            return CIPHER_CTR_ALGORITHM;
        default:
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm
                + ". Supported: aes-128-cbc, aes-192-cbc, aes-256-cbc, aes-128-ctr, aes-192-ctr, aes-256-ctr");
    }
}
```

**Step 3: Commit**
```
git add ios/Aes/lib/AesCrypt.m android/src/main/java/com/tectiv3/aes/Aes.java
git commit -m "security: strict algorithm whitelist, reject unknown algorithms"
```

---

### Task 1.5: Fix PBKDF2 Length Parameter (Android bits→bytes)

**Files:**
- Modify: `android/src/main/java/com/tectiv3/aes/Aes.java:201`

**Step 1: Fix the generateDerivedParameters call**

The iOS side already divides by 8 at line 44 (`length/8`), so iOS treats `length` as bits.
The Android side passes `length` directly to `generateDerivedParameters()` which also expects bits.
Both platforms are consistent — the parameter IS bits.

However, the README example uses `256` which means 256 bits = 32 bytes. This is actually correct on both platforms.

**Decision: Keep as bits. Document clearly in README and TypeScript types.**

No code change needed here — just documentation (covered in Phase 4).

**Step 1: Add validation for minimum length**

```java
// In pbkdf2() method, after line 199
if (length < 128) {
    throw new IllegalArgumentException("Key length must be at least 128 bits, got " + length);
}
```

iOS equivalent in `AesCrypt.m` after line 44:
```objc
if (length < 128) {
    NSLog(@"PBKDF2 error: key length must be at least 128 bits");
    return nil;
}
```

**Step 2: Commit**
```
git add ios/Aes/lib/AesCrypt.m android/src/main/java/com/tectiv3/aes/Aes.java
git commit -m "security: enforce minimum PBKDF2 key length of 128 bits"
```

---

### Task 1.6: Fix iOS CTR Cryptor Leak and Buffer Bug

**Files:**
- Modify: `ios/Aes/lib/AesCrypt.m:118-188`

**Step 1: Rewrite AESCTR with proper resource management**

```objc
+ (NSData *) AESCTR: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];

    if (ivData.length != kCCBlockSizeAES128) {
        NSLog(@"AES error: IV must be exactly 16 bytes, got %lu", (unsigned long)ivData.length);
        return nil;
    }

    NSArray *aesAlgorithms = @[@"aes-128-ctr", @"aes-192-ctr", @"aes-256-ctr"];
    size_t item = [aesAlgorithms indexOfObject:algorithm];
    size_t keyLength;
    switch (item) {
        case 0:  keyLength = kCCKeySizeAES128; break;
        case 1:  keyLength = kCCKeySizeAES192; break;
        default: keyLength = kCCKeySizeAES256; break;
    }

    if (keyData.length != keyLength) {
        NSLog(@"AES error: key length %lu does not match algorithm requirement %zu",
              (unsigned long)keyData.length, keyLength);
        return nil;
    }

    NSMutableData *buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];
    size_t numBytes = 0;

    CCCryptorRef cryptor = NULL;
    CCCryptorStatus createStatus = CCCryptorCreateWithMode(
        [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
        kCCModeCTR,
        kCCAlgorithmAES,
        ccNoPadding,
        ivData.bytes,
        keyData.bytes,
        keyLength,
        NULL, 0, 0,
        kCCModeOptionCTR_BE,
        &cryptor);

    if (createStatus != kCCSuccess) {
        NSLog(@"AES CTR error creating cryptor: %d", createStatus);
        return nil;
    }

    CCCryptorStatus updateStatus = CCCryptorUpdate(
        cryptor, data.bytes, data.length,
        buffer.mutableBytes, buffer.length, &numBytes);

    if (updateStatus != kCCSuccess) {
        CCCryptorRelease(cryptor);
        NSLog(@"AES CTR error during update: %d", updateStatus);
        return nil;
    }

    size_t finalBytes = 0;
    CCCryptorStatus finalStatus = CCCryptorFinal(
        cryptor,
        buffer.mutableBytes + numBytes,
        buffer.length - numBytes,
        &finalBytes);

    CCCryptorRelease(cryptor);

    if (finalStatus != kCCSuccess) {
        NSLog(@"AES CTR error during final: %d", finalStatus);
        return nil;
    }

    buffer.length = numBytes + finalBytes;
    return buffer;
}
```

**Step 2: Commit**
```
git add ios/Aes/lib/AesCrypt.m
git commit -m "fix: CTR mode cryptor leak, final buffer pointer, padding"
```

---

### Task 1.7: Fix Android shaX Charset and Unused Imports

**Files:**
- Modify: `android/src/main/java/com/tectiv3/aes/Aes.java:171` (charset)
- Modify: `android/src/main/java/com/tectiv3/aes/Aes.java:1-10` (unused imports)

**Step 1: Fix charset**

Line 171, change:
```java
// FROM:
md.update(data.getBytes());
// TO:
md.update(data.getBytes("UTF-8"));
```

**Step 2: Remove unused imports**

Remove lines 3, 5, 8, 9, 42:
```java
// DELETE:
import android.widget.Toast;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import com.facebook.react.bridge.Callback;
```

**Step 3: Fix PBKDF2 algorithm fallback — use else-if chain**

```java
Digest algorithmDigest;
if (algorithm.equalsIgnoreCase("sha1")) {
    algorithmDigest = new SHA1Digest();
} else if (algorithm.equalsIgnoreCase("sha256")) {
    algorithmDigest = new SHA256Digest();
} else if (algorithm.equalsIgnoreCase("sha512")) {
    algorithmDigest = new SHA512Digest();
} else {
    throw new NoSuchAlgorithmException("Unsupported PBKDF2 algorithm: " + algorithm
        + ". Supported: sha1, sha256, sha512");
}
```

**Step 4: Commit**
```
git add android/src/main/java/com/tectiv3/aes/Aes.java
git commit -m "fix: use explicit UTF-8 charset, remove unused imports, strict PBKDF2 algorithm"
```

---

### Task 1.8: Fix iOS PBKDF2 Error Return and malloc Checks

**Files:**
- Modify: `ios/Aes/lib/AesCrypt.m:68-70` (return nil instead of empty string)
- Modify: `ios/Aes/lib/AesCrypt.m:215,224,239,247` (malloc null checks)

**Step 1: Fix PBKDF2 error return**

Line 70, change:
```objc
// FROM:
return @"";
// TO:
return nil;
```

**Step 2: Add malloc null checks to hmac and sha methods**

For each `malloc` call (hmac256, hmac512, sha256, sha512), add:
```objc
void* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
if (buffer == NULL) {
    return nil;
}
```

**Step 3: Commit**
```
git add ios/Aes/lib/AesCrypt.m
git commit -m "fix: PBKDF2 returns nil on error, add malloc null checks"
```

---

## Phase 2: Architecture Modernization

### Task 2.1: Set Up react-native-builder-bob and TypeScript

**Files:**
- Create: `src/index.ts`
- Create: `src/NativeAes.ts` (Codegen spec)
- Create: `tsconfig.json`
- Create: `tsconfig.build.json`
- Create: `.eslintrc.js`
- Modify: `package.json` (major restructuring)
- Delete: `index.js`
- Delete: `index.d.ts`

**Step 1: Install dev dependencies**

```bash
npm install --save-dev react-native-builder-bob typescript @types/react-native eslint prettier
```

**Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "rootDir": ".",
    "paths": {
      "react-native-aes-crypto": ["./src/index"]
    },
    "allowUnreachableCode": false,
    "allowUnusedLabels": false,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "jsx": "react",
    "lib": ["esnext"],
    "module": "esnext",
    "moduleResolution": "node",
    "noFallthroughCasesInSwitch": true,
    "noImplicitReturns": true,
    "noImplicitUseStrict": false,
    "noStrictGenericChecks": false,
    "noUncheckedIndexedAccess": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "resolveJsonModule": true,
    "skipLibCheck": true,
    "strict": true,
    "target": "esnext",
    "verbatimModuleSyntax": false
  },
  "exclude": ["lib", "node_modules", "example"]
}
```

**Step 3: Create tsconfig.build.json**

```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "rootDir": "src"
  },
  "include": ["src"]
}
```

**Step 4: Create Codegen spec — `src/NativeAes.ts`**

```typescript
import type { TurboModule } from 'react-native'
import { TurboModuleRegistry } from 'react-native'

type AesAlgorithm =
    | 'aes-128-cbc'
    | 'aes-192-cbc'
    | 'aes-256-cbc'
    | 'aes-128-ctr'
    | 'aes-192-ctr'
    | 'aes-256-ctr'

type PbkdfAlgorithm = 'sha1' | 'sha256' | 'sha512'

export interface Spec extends TurboModule {
    encrypt(data: string, key: string, iv: string, algorithm: string): Promise<string>
    decrypt(ciphertext: string, key: string, iv: string, algorithm: string): Promise<string>
    pbkdf2(
        password: string,
        salt: string,
        cost: number,
        length: number,
        algorithm: string
    ): Promise<string>
    hmac256(data: string, key: string): Promise<string>
    hmac512(data: string, key: string): Promise<string>
    sha1(text: string): Promise<string>
    sha256(text: string): Promise<string>
    sha512(text: string): Promise<string>
    randomUuid(): Promise<string>
    randomKey(length: number): Promise<string>
}

export default TurboModuleRegistry.getEnforcing<Spec>('Aes')
```

Note: Codegen only supports primitive types in the spec (string, number, boolean), so algorithm type unions are enforced in the TS wrapper, not in the spec itself.

**Step 5: Create `src/index.ts`**

```typescript
import { NativeModules } from 'react-native'
import type { Spec } from './NativeAes'

const LINKING_ERROR =
    'The package "react-native-aes-crypto" doesn\'t seem to be linked. Make sure:\n\n' +
    '- You rebuilt the app after installing the package\n' +
    '- If you are using a bare React Native project, you ran "pod install"\n' +
    '- You are not using Expo Go\n'

type AesAlgorithm =
    | 'aes-128-cbc'
    | 'aes-192-cbc'
    | 'aes-256-cbc'
    | 'aes-128-ctr'
    | 'aes-192-ctr'
    | 'aes-256-ctr'

type PbkdfAlgorithm = 'sha1' | 'sha256' | 'sha512'

const VALID_AES_ALGORITHMS = new Set<string>([
    'aes-128-cbc',
    'aes-192-cbc',
    'aes-256-cbc',
    'aes-128-ctr',
    'aes-192-ctr',
    'aes-256-ctr',
])

const VALID_PBKDF2_ALGORITHMS = new Set<string>(['sha1', 'sha256', 'sha512'])

// Resolve native module: TurboModule (new arch) or bridge (old arch)
const isTurboModuleEnabled = global.__turboModuleProxy != null

const AesModule: Spec = isTurboModuleEnabled
    ? require('./NativeAes').default
    : NativeModules.Aes

if (!AesModule) {
    throw new Error(LINKING_ERROR)
}

export function encrypt(
    data: string,
    key: string,
    iv: string,
    algorithm: AesAlgorithm
): Promise<string> {
    if (!data) throw new Error('data must not be empty')
    if (!key) throw new Error('key must not be empty')
    if (!iv) throw new Error('iv must not be empty')
    if (!VALID_AES_ALGORITHMS.has(algorithm)) {
        throw new Error(
            `Unsupported algorithm "${algorithm}". Use: ${[...VALID_AES_ALGORITHMS].join(', ')}`
        )
    }
    return AesModule.encrypt(data, key, iv, algorithm)
}

export function decrypt(
    ciphertext: string,
    key: string,
    iv: string,
    algorithm: AesAlgorithm
): Promise<string> {
    if (!ciphertext) throw new Error('ciphertext must not be empty')
    if (!key) throw new Error('key must not be empty')
    if (!iv) throw new Error('iv must not be empty')
    if (!VALID_AES_ALGORITHMS.has(algorithm)) {
        throw new Error(
            `Unsupported algorithm "${algorithm}". Use: ${[...VALID_AES_ALGORITHMS].join(', ')}`
        )
    }
    return AesModule.decrypt(ciphertext, key, iv, algorithm)
}

export function pbkdf2(
    password: string,
    salt: string,
    cost: number,
    length: number,
    algorithm: PbkdfAlgorithm
): Promise<string> {
    if (!password) throw new Error('password must not be empty')
    if (!salt) throw new Error('salt must not be empty')
    if (cost < 1) throw new Error('cost must be a positive integer')
    if (length < 128) throw new Error('length must be at least 128 (bits)')
    if (!VALID_PBKDF2_ALGORITHMS.has(algorithm)) {
        throw new Error(
            `Unsupported algorithm "${algorithm}". Use: ${[...VALID_PBKDF2_ALGORITHMS].join(', ')}`
        )
    }
    return AesModule.pbkdf2(password, salt, cost, length, algorithm)
}

export function hmac256(data: string, key: string): Promise<string> {
    if (!data) throw new Error('data must not be empty')
    if (!key) throw new Error('key must not be empty')
    return AesModule.hmac256(data, key)
}

export function hmac512(data: string, key: string): Promise<string> {
    if (!data) throw new Error('data must not be empty')
    if (!key) throw new Error('key must not be empty')
    return AesModule.hmac512(data, key)
}

/** @deprecated SHA-1 is cryptographically broken for collision resistance. Use sha256 or sha512. */
export function sha1(text: string): Promise<string> {
    if (!text) throw new Error('text must not be empty')
    return AesModule.sha1(text)
}

export function sha256(text: string): Promise<string> {
    if (!text) throw new Error('text must not be empty')
    return AesModule.sha256(text)
}

export function sha512(text: string): Promise<string> {
    if (!text) throw new Error('text must not be empty')
    return AesModule.sha512(text)
}

export function randomUuid(): Promise<string> {
    return AesModule.randomUuid()
}

export function randomKey(length: number): Promise<string> {
    if (length < 1) throw new Error('length must be a positive integer')
    return AesModule.randomKey(length)
}

export type { AesAlgorithm, PbkdfAlgorithm }

export default AesModule
```

**Step 6: Update package.json**

```json
{
    "name": "react-native-aes-crypto",
    "version": "4.0.0",
    "description": "AES encryption/decryption native module for React Native",
    "main": "lib/commonjs/index",
    "module": "lib/module/index",
    "types": "lib/typescript/src/index.d.ts",
    "react-native": "src/index",
    "source": "src/index",
    "files": [
        "src",
        "lib",
        "android",
        "ios",
        "react-native-aes.podspec",
        "!android/build",
        "!ios/build",
        "!**/__tests__"
    ],
    "scripts": {
        "prepare": "bob build",
        "typecheck": "tsc --noEmit -p tsconfig.build.json",
        "lint": "eslint src/",
        "format": "prettier --write src/"
    },
    "keywords": [
        "react-native",
        "aes",
        "crypto",
        "encryption",
        "decryption",
        "pbkdf2",
        "hmac",
        "sha256",
        "sha512"
    ],
    "repository": {
        "type": "git",
        "url": "git://github.com/tectiv3/react-native-aes.git"
    },
    "author": "tectiv3",
    "license": "MIT",
    "bugs": {
        "url": "https://github.com/tectiv3/react-native-aes/issues"
    },
    "homepage": "https://github.com/tectiv3/react-native-aes",
    "peerDependencies": {
        "react": ">=18.0.0",
        "react-native": ">=0.75.0"
    },
    "devDependencies": {
        "react": "^18.0.0",
        "react-native": "^0.75.0",
        "react-native-builder-bob": "^0.35.0",
        "typescript": "^5.0.0"
    },
    "engines": {
        "node": ">=18"
    },
    "codegenConfig": {
        "name": "RNAesSpec",
        "type": "modules",
        "jsSrcsDir": "src"
    },
    "react-native-builder-bob": {
        "source": "src",
        "output": "lib",
        "targets": [
            "commonjs",
            "module",
            ["typescript", { "project": "tsconfig.build.json" }]
        ]
    }
}
```

**Step 7: Delete old files**

```bash
rm index.js index.d.ts
```

**Step 8: Add `lib/` to .gitignore**

Append to `.gitignore`:
```
lib/
node_modules/
```

**Step 9: Commit**
```
git add -A
git commit -m "feat: rewrite JS layer in TypeScript with input validation and Codegen spec"
```

---

### Task 2.2: Update iOS — TurboModule Support + Fixes

**Files:**
- Modify: `ios/Aes/Aes.h`
- Modify: `ios/Aes/Aes.m` → rename to `ios/Aes/Aes.mm`
- Modify: `react-native-aes.podspec`

**Step 1: Update podspec**

```ruby
require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
    s.name         = "react-native-aes"
    s.version      = package["version"]
    s.summary      = package["description"]
    s.homepage     = package["homepage"]
    s.license      = package["license"]
    s.authors      = package["author"]
    s.platforms    = { :ios => "13.0", :visionos => "1.0" }
    s.source       = { :git => package["repository"]["url"], :tag => "v#{s.version}" }
    s.source_files = "ios/**/*.{h,m,mm}"

    if defined?(install_modules_dependencies)
        install_modules_dependencies(s)
    else
        s.dependency "React-Core"
    end
end
```

**Step 2: Update Aes.h for dual architecture**

```objc
#import <React/RCTBridgeModule.h>

#ifdef RCT_NEW_ARCH_ENABLED
#import <RNAesSpec/RNAesSpec.h>
#endif

#ifdef RCT_NEW_ARCH_ENABLED
@interface Aes : NSObject <NativeAesSpec>
#else
@interface Aes : NSObject <RCTBridgeModule>
#endif

@end
```

**Step 3: Rename Aes.m → Aes.mm and add TurboModule conformance**

```bash
mv ios/Aes/Aes.m ios/Aes/Aes.mm
```

Add at the bottom of `Aes.mm`, before `@end`:

```objc
#ifdef RCT_NEW_ARCH_ENABLED
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeAesSpecJSI>(params);
}
#endif
```

Also add at the top of the implementation:
```objc
+ (BOOL)requiresMainQueueSetup {
    return NO;
}
```

And remove all the `NSError *error = nil;` lines that pass nil to reject — create proper NSError objects:
```objc
// REPLACE pattern:
//   NSError *error = nil;
//   ...
//   reject(@"encrypt_fail", @"Encrypt error", error);
// WITH:
//   reject(@"encrypt_fail", @"Encrypt error", nil);
```
(The nil-initialized NSError was doing nothing anyway.)

**Step 4: Remove Aes.xcodeproj** (not needed with CocoaPods/new arch)

```bash
rm -rf ios/Aes.xcodeproj
```

**Step 5: Commit**
```
git add -A
git commit -m "feat(ios): add TurboModule support, update podspec for iOS 13+"
```

---

### Task 2.3: Update Android — Kotlin, Modern Gradle, TurboModule

**Files:**
- Create: `android/src/main/java/com/tectiv3/aes/AesModule.kt` (replaces Aes.java)
- Modify: `android/src/main/java/com/tectiv3/aes/AesPackage.java` → `AesPackage.kt`
- Modify: `android/build.gradle`
- Delete: `android/src/main/java/com/tectiv3/aes/Aes.java`

**Step 1: Rewrite build.gradle**

```gradle
buildscript {
    ext.safeExtGet = {prop, fallback ->
        rootProject.ext.has(prop) ? rootProject.ext.get(prop) : fallback
    }
}

apply plugin: 'com.android.library'
apply plugin: 'kotlin-android'

if (project.hasProperty("newArchEnabled") && project.newArchEnabled == "true") {
    apply plugin: 'com.facebook.react'
}

android {
    namespace = "com.tectiv3.aes"
    compileSdkVersion safeExtGet('compileSdkVersion', 34)

    defaultConfig {
        minSdkVersion safeExtGet('minSdkVersion', 23)
        targetSdkVersion safeExtGet('targetSdkVersion', 34)
    }

    lint {
        abortOnError false
    }

    sourceSets {
        main.java.srcDirs += 'src/main/kotlin'
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = '17'
    }
}

repositories {
    mavenLocal()
    google()
    mavenCentral()
}

dependencies {
    implementation 'com.facebook.react:react-native:+'
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
}
```

**Step 2: Create AesModule.kt**

This is the full Kotlin rewrite of `Aes.java` with all security fixes applied. Key changes:
- Kotlin null safety
- Proper error codes (not just "-1")
- No SpongyCastle (BouncyCastle instead)
- No static zero IV
- Explicit UTF-8 everywhere
- NoPadding for CTR
- Strict algorithm validation
- TurboModule-compatible via Codegen base class

```kotlin
package com.tectiv3.aes

import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.util.encoders.Hex
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AesModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = "Aes"

    companion object {
        private const val CIPHER_CBC = "AES/CBC/PKCS7Padding"
        private const val CIPHER_CTR = "AES/CTR/NoPadding"

        private val ALGORITHM_MAP = mapOf(
            "aes-128-cbc" to CIPHER_CBC,
            "aes-192-cbc" to CIPHER_CBC,
            "aes-256-cbc" to CIPHER_CBC,
            "aes-128-ctr" to CIPHER_CTR,
            "aes-192-ctr" to CIPHER_CTR,
            "aes-256-ctr" to CIPHER_CTR,
        )

        private fun resolveAlgorithm(algorithm: String): String {
            return ALGORITHM_MAP[algorithm.lowercase()]
                ?: throw IllegalArgumentException(
                    "Unsupported algorithm: $algorithm. Supported: ${ALGORITHM_MAP.keys.joinToString()}"
                )
        }

        private fun encryptInternal(text: String, hexKey: String, hexIv: String, algorithm: String): String {
            val key = Hex.decode(hexKey)
            val iv = Hex.decode(hexIv)

            require(key.size == 16 || key.size == 24 || key.size == 32) {
                "Key must be 16, 24, or 32 bytes for AES-128/192/256, got ${key.size}"
            }
            require(iv.size == 16) { "IV must be exactly 16 bytes, got ${iv.size}" }

            val cipher = Cipher.getInstance(algorithm)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            val encrypted = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
            return Base64.encodeToString(encrypted, Base64.NO_WRAP)
        }

        private fun decryptInternal(ciphertext: String, hexKey: String, hexIv: String, algorithm: String): String {
            val key = Hex.decode(hexKey)
            val iv = Hex.decode(hexIv)

            require(key.size == 16 || key.size == 24 || key.size == 32) {
                "Key must be 16, 24, or 32 bytes for AES-128/192/256, got ${key.size}"
            }
            require(iv.size == 16) { "IV must be exactly 16 bytes, got ${iv.size}" }

            val cipher = Cipher.getInstance(algorithm)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            val decrypted = cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP))
            return String(decrypted, Charsets.UTF_8)
        }
    }

    @ReactMethod
    fun encrypt(data: String, key: String, iv: String, algorithm: String, promise: Promise) {
        try {
            val cipherAlg = resolveAlgorithm(algorithm)
            promise.resolve(encryptInternal(data, key, iv, cipherAlg))
        } catch (e: Exception) {
            promise.reject("ENCRYPT_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun decrypt(data: String, key: String, iv: String, algorithm: String, promise: Promise) {
        try {
            val cipherAlg = resolveAlgorithm(algorithm)
            promise.resolve(decryptInternal(data, key, iv, cipherAlg))
        } catch (e: Exception) {
            promise.reject("DECRYPT_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun pbkdf2(password: String, salt: String, cost: Int, length: Int, algorithm: String, promise: Promise) {
        try {
            require(length >= 128) { "Key length must be at least 128 bits, got $length" }

            val digest = when (algorithm.lowercase()) {
                "sha1" -> SHA1Digest()
                "sha256" -> SHA256Digest()
                "sha512" -> SHA512Digest()
                else -> throw IllegalArgumentException(
                    "Unsupported PBKDF2 algorithm: $algorithm. Supported: sha1, sha256, sha512"
                )
            }

            val gen = PKCS5S2ParametersGenerator(digest)
            gen.init(password.toByteArray(Charsets.UTF_8), salt.toByteArray(Charsets.UTF_8), cost)
            val key = (gen.generateDerivedParameters(length) as KeyParameter).key
            promise.resolve(bytesToHex(key))
        } catch (e: Exception) {
            promise.reject("PBKDF2_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun hmac256(data: String, key: String, promise: Promise) {
        try {
            promise.resolve(hmacInternal(data, key, "HmacSHA256"))
        } catch (e: Exception) {
            promise.reject("HMAC_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun hmac512(data: String, key: String, promise: Promise) {
        try {
            promise.resolve(hmacInternal(data, key, "HmacSHA512"))
        } catch (e: Exception) {
            promise.reject("HMAC_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun sha1(data: String, promise: Promise) {
        try {
            promise.resolve(shaInternal(data, "SHA-1"))
        } catch (e: Exception) {
            promise.reject("SHA_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun sha256(data: String, promise: Promise) {
        try {
            promise.resolve(shaInternal(data, "SHA-256"))
        } catch (e: Exception) {
            promise.reject("SHA_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun sha512(data: String, promise: Promise) {
        try {
            promise.resolve(shaInternal(data, "SHA-512"))
        } catch (e: Exception) {
            promise.reject("SHA_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun randomUuid(promise: Promise) {
        try {
            promise.resolve(UUID.randomUUID().toString())
        } catch (e: Exception) {
            promise.reject("UUID_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun randomKey(length: Int, promise: Promise) {
        try {
            require(length > 0) { "length must be a positive integer" }
            val bytes = ByteArray(length)
            SecureRandom().nextBytes(bytes)
            promise.resolve(bytesToHex(bytes))
        } catch (e: Exception) {
            promise.reject("RANDOM_ERROR", e.message, e)
        }
    }

    private fun hmacInternal(text: String, hexKey: String, algorithm: String): String {
        val keyBytes = Hex.decode(hexKey)
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(keyBytes, algorithm))
        return bytesToHex(mac.doFinal(text.toByteArray(Charsets.UTF_8)))
    }

    private fun shaInternal(data: String, algorithm: String): String {
        val md = MessageDigest.getInstance(algorithm)
        md.update(data.toByteArray(Charsets.UTF_8))
        return bytesToHex(md.digest())
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        val hexArray = "0123456789abcdef".toCharArray()
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = hexArray[v ushr 4]
            hexChars[i * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }
}
```

**Step 3: Create AesPackage.kt**

```kotlin
package com.tectiv3.aes

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

class AesPackage : ReactPackage {
    override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> {
        return listOf(AesModule(reactContext))
    }

    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> {
        return emptyList()
    }
}
```

**Step 4: Delete old Java files**

```bash
rm android/src/main/java/com/tectiv3/aes/Aes.java
rm android/src/main/java/com/tectiv3/aes/AesPackage.java
```

Create kotlin source directory:
```bash
mkdir -p android/src/main/kotlin/com/tectiv3/aes
```

Move/create the .kt files in the kotlin directory, or keep them in `java/` (Gradle `sourceSets` config handles either).

**Step 5: Remove SpongyCastle PG dependency and old gradle config**

The `build.gradle` from Step 1 already handles this. Remove the old `gradle/` directory if present:
```bash
rm -rf android/gradle
```

**Step 6: Commit**
```
git add -A
git commit -m "feat(android): rewrite in Kotlin, BouncyCastle, modern Gradle, compileSdk 34"
```

---

### Task 2.4: Update README with v4 Migration Notice

**Files:**
- Modify: `README.md`

**Step 1: Write the updated README**

The README should include:
- v4 compatibility notice at the top (like quick-crypto)
- Modern async/await examples
- Security guidance section
- API reference with parameter descriptions and encoding info
- Breaking changes from v3

Key section to add at the top:

```markdown
> **Note:** Version 4.x requires React Native 0.75 or higher. If you need to support
> earlier versions of React Native, please use version 3.x of this library.
```

Breaking changes section:

```markdown
## Migrating from v3

- **Minimum RN 0.75**, iOS 13.0, Android API 23
- **IV is now required** — passing null/empty IV throws an error (v3 silently used zeros)
- **`pbkdf2Sync` removed** — use the async `pbkdf2` instead
- **CTR output is now base64** — v3 returned hex for CTR, base64 for CBC. v4 uses base64 for both
- **Named exports** — `import { encrypt, decrypt } from 'react-native-aes-crypto'` (default export still works)
- **Strict algorithm validation** — unknown algorithm strings now throw instead of falling back
```

Security guidance section:

```markdown
## Security Guidance

- **Always use a random IV** — generate with `randomKey(16)` for each encryption
- **Never reuse an IV** with the same key
- **Use sufficient PBKDF2 iterations** — minimum 100,000 for SHA-256, 210,000+ recommended (OWASP 2023)
- **Prefer AES-256-CBC** with HMAC verification, or wait for GCM support
- **The `length` parameter in `pbkdf2` is in bits** — use 256 for a 32-byte key
- **`sha1` is deprecated** — use `sha256` or `sha512` instead
```

**Step 2: Commit**
```
git add README.md
git commit -m "docs: update README for v4 with migration guide and security guidance"
```

---

## Phase 3: Feature Additions

### Task 3.1: Add AES-GCM Support (Authenticated Encryption)

**Files:**
- Modify: `src/NativeAes.ts` (add encryptGcm/decryptGcm to spec)
- Modify: `src/index.ts` (add wrapper functions)
- Modify: `ios/Aes/lib/AesCrypt.h` (add GCM method signatures)
- Modify: `ios/Aes/lib/AesCrypt.m` (implement GCM with CCCryptorGCM)
- Modify: `ios/Aes/Aes.mm` (bridge GCM methods)
- Modify: `android/src/main/kotlin/com/tectiv3/aes/AesModule.kt` (implement GCM)

**Step 1: Add to Codegen spec**

Add to `src/NativeAes.ts` Spec interface:
```typescript
    encryptGcm(
        data: string,
        key: string,
        iv: string,
        aad: string,
        tagLength: number
    ): Promise<string>  // returns base64(ciphertext + tag)

    decryptGcm(
        ciphertext: string,
        key: string,
        iv: string,
        aad: string,
        tagLength: number
    ): Promise<string>
```

**Step 2: Add JS wrapper in `src/index.ts`**

```typescript
export function encryptGcm(
    data: string,
    key: string,
    iv: string,
    aad: string = '',
    tagLength: number = 128
): Promise<string> {
    if (!data) throw new Error('data must not be empty')
    if (!key) throw new Error('key must not be empty')
    if (!iv) throw new Error('iv must not be empty')
    if (![96, 104, 112, 120, 128].includes(tagLength)) {
        throw new Error('tagLength must be 96, 104, 112, 120, or 128')
    }
    return AesModule.encryptGcm(data, key, iv, aad, tagLength)
}

export function decryptGcm(
    ciphertext: string,
    key: string,
    iv: string,
    aad: string = '',
    tagLength: number = 128
): Promise<string> {
    if (!ciphertext) throw new Error('ciphertext must not be empty')
    if (!key) throw new Error('key must not be empty')
    if (!iv) throw new Error('iv must not be empty')
    return AesModule.decryptGcm(ciphertext, key, iv, aad, tagLength)
}
```

**Step 3: Implement iOS GCM**

Use `CCCryptorGCM` API (available iOS 13+):

```objc
+ (NSString *) encryptGcm:(NSString *)clearText key:(NSString *)key iv:(NSString *)iv
                       aad:(NSString *)aad tagLength:(NSInteger)tagLengthBits {
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
    NSData *aadData = [aad dataUsingEncoding:NSUTF8StringEncoding];
    NSData *plainData = [clearText dataUsingEncoding:NSUTF8StringEncoding];

    if (keyData.length != 16 && keyData.length != 24 && keyData.length != 32) return nil;
    if (ivData.length < 1) return nil;

    size_t tagLength = tagLengthBits / 8;
    NSMutableData *cipherData = [NSMutableData dataWithLength:plainData.length];
    NSMutableData *tagData = [NSMutableData dataWithLength:tagLength];

    CCCryptorStatus status = CCCryptorGCMOneshotEncrypt(
        kCCAlgorithmAES,
        keyData.bytes, keyData.length,
        ivData.bytes, ivData.length,
        aadData.bytes, aadData.length,
        plainData.bytes, plainData.length,
        cipherData.mutableBytes,
        tagData.mutableBytes, tagLength);

    if (status != kCCSuccess) return nil;

    // Append tag to ciphertext
    NSMutableData *result = [NSMutableData dataWithData:cipherData];
    [result appendData:tagData];
    return [result base64EncodedStringWithOptions:0];
}
```

Implement matching `decryptGcm:` using `CCCryptorGCMOneshotDecrypt`.

**Step 4: Implement Android GCM**

```kotlin
@ReactMethod
fun encryptGcm(data: String, key: String, iv: String, aad: String, tagLength: Int, promise: Promise) {
    try {
        val keyBytes = Hex.decode(key)
        val ivBytes = Hex.decode(iv)
        require(keyBytes.size == 16 || keyBytes.size == 24 || keyBytes.size == 32)
        require(ivBytes.isNotEmpty()) { "IV must not be empty for GCM" }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = javax.crypto.spec.GCMParameterSpec(tagLength, ivBytes)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), spec)
        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        }
        val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        // encrypted already contains ciphertext + tag (Java GCM appends tag)
        promise.resolve(Base64.encodeToString(encrypted, Base64.NO_WRAP))
    } catch (e: Exception) {
        promise.reject("ENCRYPT_GCM_ERROR", e.message, e)
    }
}
```

Implement matching `decryptGcm`.

**Step 5: Commit**
```
git add -A
git commit -m "feat: add AES-GCM authenticated encryption support"
```

---

### Task 3.2: Consistent Output Encoding

**Files:**
- Modify: `ios/Aes/lib/AesCrypt.m:190-210` (encrypt/decrypt methods)

**Step 1: Make CTR encrypt return base64 (iOS)**

This was already handled in Task 1.4 when we rewrote the `encrypt:` dispatch to use base64 for both modes. Verify the decrypt side also handles base64 input for CTR:

```objc
+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv algorithm: (NSString *)algorithm {
    NSSet *ctrAlgorithms = [NSSet setWithArray:@[@"aes-128-ctr", @"aes-192-ctr", @"aes-256-ctr"]];
    NSSet *cbcAlgorithms = [NSSet setWithArray:@[@"aes-128-cbc", @"aes-192-cbc", @"aes-256-cbc"]];

    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:cipherText options:0];
    if (!cipherData) return nil;

    if ([ctrAlgorithms containsObject:algorithm]) {
        NSData *result = [self AESCTR:@"decrypt" data:cipherData key:key iv:iv algorithm:algorithm];
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    } else if ([cbcAlgorithms containsObject:algorithm]) {
        NSData *result = [self AESCBC:@"decrypt" data:cipherData key:key iv:iv algorithm:algorithm];
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }
    return nil;
}
```

**Step 2: Verify Android already uses base64 for both modes**

Android's `encrypt()` already returns `Base64.encodeToString()` and `decrypt()` already does `Base64.decode()` regardless of mode. Confirmed — no change needed on Android.

**Step 3: Commit**
```
git add ios/Aes/lib/AesCrypt.m
git commit -m "fix: consistent base64 encoding for both CBC and CTR modes"
```

---

### Task 3.3: Remove pbkdf2Sync

**Files:**
- Modify: `ios/Aes/Aes.mm` (remove the RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD)
- Already removed from Android in Task 2.3 (not in AesModule.kt)

**Step 1: Remove from iOS**

Delete the `pbkdf2Sync` method (lines 41-43 in original Aes.m):

```objc
// DELETE this entire method:
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(pbkdf2Sync:...)
```

**Step 2: Commit**
```
git add ios/Aes/Aes.mm
git commit -m "breaking: remove pbkdf2Sync (blocks JS thread)"
```

---

## Phase 4: Quality & DX

### Task 4.1: Add Cross-Platform Test Vectors

**Files:**
- Create: `src/__tests__/validation.test.ts`
- Modify: `package.json` (add jest config)

**Step 1: Add jest**

```bash
npm install --save-dev jest @types/jest ts-jest
```

**Step 2: Create validation tests**

These test the JS-side validation logic (not native — native needs an example app or detox):

```typescript
import { encrypt, decrypt, pbkdf2, hmac256, randomKey } from '../index'

// Mock the native module
jest.mock('../NativeAes', () => ({
    default: {
        encrypt: jest.fn().mockResolvedValue('mockCipher'),
        decrypt: jest.fn().mockResolvedValue('mockPlain'),
        pbkdf2: jest.fn().mockResolvedValue('mockKey'),
        hmac256: jest.fn().mockResolvedValue('mockHmac'),
        hmac512: jest.fn().mockResolvedValue('mockHmac'),
        sha1: jest.fn().mockResolvedValue('mockHash'),
        sha256: jest.fn().mockResolvedValue('mockHash'),
        sha512: jest.fn().mockResolvedValue('mockHash'),
        randomUuid: jest.fn().mockResolvedValue('mock-uuid'),
        randomKey: jest.fn().mockResolvedValue('deadbeef'),
    },
}))

describe('input validation', () => {
    it('rejects empty data for encrypt', () => {
        expect(() => encrypt('', 'key', 'iv', 'aes-256-cbc')).toThrow('data must not be empty')
    })

    it('rejects empty key for encrypt', () => {
        expect(() => encrypt('data', '', 'iv', 'aes-256-cbc')).toThrow('key must not be empty')
    })

    it('rejects empty iv for encrypt', () => {
        expect(() => encrypt('data', 'key', '', 'aes-256-cbc')).toThrow('iv must not be empty')
    })

    it('rejects invalid algorithm', () => {
        expect(() => encrypt('data', 'key', 'iv', 'aes-256-ecb' as any)).toThrow('Unsupported algorithm')
    })

    it('rejects pbkdf2 with low length', () => {
        expect(() => pbkdf2('pass', 'salt', 1000, 64, 'sha256')).toThrow('at least 128')
    })

    it('rejects pbkdf2 with invalid algorithm', () => {
        expect(() => pbkdf2('pass', 'salt', 1000, 256, 'md5' as any)).toThrow('Unsupported algorithm')
    })

    it('rejects randomKey with zero length', () => {
        expect(() => randomKey(0)).toThrow('positive integer')
    })

    it('accepts valid encrypt call', async () => {
        const result = await encrypt('hello', 'key', 'iv', 'aes-256-cbc')
        expect(result).toBe('mockCipher')
    })
})
```

**Step 3: Add test script to package.json**

```json
"scripts": {
    "test": "jest",
    ...
}
```

Add jest config to package.json:
```json
"jest": {
    "preset": "ts-jest",
    "testEnvironment": "node",
    "testPathPattern": "src/__tests__/"
}
```

**Step 4: Run tests**
```bash
npm test
```
Expected: all 8 tests pass.

**Step 5: Commit**
```
git add -A
git commit -m "test: add JS-side input validation tests"
```

---

### Task 4.2: Add .npmignore and Package Hygiene

**Files:**
- Create: `.npmignore`
- Modify: `.prettierrc.js` → `.prettierrc.json` (ESM compat)
- Modify: `.gitignore`

**Step 1: Create .npmignore**

```
.DS_Store
.git
.github
.prettierrc*
.eslintrc*
.gitignore
.claude
.serena
docs/
src/__tests__/
tsconfig*.json
jest.config.*
*.tgz
node_modules/
android/build/
ios/build/
```

**Step 2: Convert prettierrc to JSON**

Rename and convert:
```json
{
    "printWidth": 100,
    "tabWidth": 4,
    "useTabs": false,
    "semi": false,
    "singleQuote": true,
    "trailingComma": "es5",
    "bracketSpacing": true,
    "arrowParens": "avoid"
}
```

**Step 3: Update .gitignore**

```
.DS_Store
node_modules/
lib/
android/build/
android/.gradle/
android/.idea/
ios/build/
ios/Pods/
*.tgz
```

**Step 4: Commit**
```
git add -A
git commit -m "chore: add .npmignore, clean up config files"
```

---

### Task 4.3: Add CHANGELOG.md

**Files:**
- Create: `CHANGELOG.md`

**Step 1: Write initial changelog**

```markdown
# Changelog

## [4.0.0] - 2026-03-XX

### Breaking Changes
- Minimum React Native 0.75, iOS 13.0, Android API 23
- IV is now required — passing null/empty throws instead of using zeros
- `pbkdf2Sync` removed — use async `pbkdf2` instead
- CTR mode output changed from hex to base64 (now consistent with CBC)
- Unknown algorithm strings now throw instead of falling back silently
- Package now uses named exports alongside default export

### Security Fixes
- **CRITICAL**: Reject null/empty IV (previously fell back to all-zero IV)
- **CRITICAL**: Fix CTR mode padding (NoPadding instead of PKCS5/7)
- **HIGH**: Validate key length against algorithm selection
- **HIGH**: Strict algorithm whitelist — reject unknown values
- **MEDIUM**: PBKDF2 returns nil on error instead of empty string (iOS)
- **MEDIUM**: Enforce minimum PBKDF2 key length (128 bits)
- **MEDIUM**: Fix iOS CTR cryptor handle leak on error paths
- **MEDIUM**: Fix iOS CTR CCCryptorFinal buffer pointer arithmetic
- **LOW**: Fix Android shaX charset to explicit UTF-8
- **LOW**: Add malloc NULL checks for hash/HMAC buffers (iOS)

### Added
- AES-GCM authenticated encryption (`encryptGcm`, `decryptGcm`)
- TypeScript source with full type safety and input validation
- TurboModule support (React Native New Architecture)
- Codegen spec for type-safe native bridge
- JS-side input validation with descriptive error messages
- Security guidance in README
- Unit tests for input validation

### Changed
- Android rewritten in Kotlin
- Android: BouncyCastle replaces unmaintained SpongyCastle
- Android: compileSdk 34, minSdk 23
- iOS: deployment target 13.0
- Build system: react-native-builder-bob
- Proper error codes instead of generic "-1"

### Removed
- `pbkdf2Sync` (blocked JS thread)
- SpongyCastle dependency
- Legacy `react-native link` support
- `Aes.xcodeproj` (CocoaPods-only now)
```

**Step 2: Commit**
```
git add CHANGELOG.md
git commit -m "docs: add CHANGELOG for v4.0.0"
```

---

## Summary of Tasks

| Phase | Task | Description | Estimated Complexity |
|-------|------|-------------|---------------------|
| 1.1 | Reject null IV | Both platforms | Low |
| 1.2 | Fix CTR padding | Both platforms | Low |
| 1.3 | Validate key length | Both platforms | Low |
| 1.4 | Strict algorithm whitelist | Both platforms | Low |
| 1.5 | PBKDF2 min length | Both platforms | Low |
| 1.6 | Fix CTR cryptor leak | iOS | Medium |
| 1.7 | Fix charset + imports | Android | Low |
| 1.8 | Fix PBKDF2 error + malloc | iOS | Low |
| 2.1 | TypeScript + builder-bob | JS layer | High |
| 2.2 | iOS TurboModule | iOS | High |
| 2.3 | Android Kotlin + Gradle | Android | High |
| 2.4 | Update README | Docs | Medium |
| 3.1 | AES-GCM | Both platforms | High |
| 3.2 | Consistent encoding | iOS | Low |
| 3.3 | Remove pbkdf2Sync | iOS | Low |
| 4.1 | Tests | JS | Medium |
| 4.2 | Package hygiene | Config | Low |
| 4.3 | Changelog | Docs | Low |

**Dependency order:** Phase 1 (any order) → Phase 2 (2.1 first, then 2.2/2.3 in parallel, then 2.4) → Phase 3 (any order) → Phase 4 (any order)
