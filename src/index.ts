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

const HEX_RE = /^[0-9a-fA-F]*$/

// TurboModule (new arch) or bridge (old arch)
const isTurboModuleEnabled = (global as any).__turboModuleProxy != null

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
    if (!HEX_RE.test(key)) throw new Error('key must be a hex-encoded string')
    return AesModule.hmac256(data, key)
}

export function hmac512(data: string, key: string): Promise<string> {
    if (!data) throw new Error('data must not be empty')
    if (!key) throw new Error('key must not be empty')
    if (!HEX_RE.test(key)) throw new Error('key must be a hex-encoded string')
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

const VALID_GCM_TAG_LENGTHS = new Set([96, 104, 112, 120, 128])

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
    if (iv.length !== 24) throw new Error('GCM IV must be exactly 12 bytes (24 hex characters)')
    if (!VALID_GCM_TAG_LENGTHS.has(tagLength)) {
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
    if (iv.length !== 24) throw new Error('GCM IV must be exactly 12 bytes (24 hex characters)')
    if (!VALID_GCM_TAG_LENGTHS.has(tagLength)) {
        throw new Error('tagLength must be 96, 104, 112, 120, or 128')
    }
    return AesModule.decryptGcm(ciphertext, key, iv, aad, tagLength)
}

export function randomUuid(): Promise<string> {
    return AesModule.randomUuid()
}

/** @param length Number of random bytes to generate (not bits). Returns hex string of `length * 2` chars. */
export function randomKey(length: number): Promise<string> {
    if (length < 1) throw new Error('length must be a positive integer')
    return AesModule.randomKey(length)
}

export type { AesAlgorithm, PbkdfAlgorithm }

/** Raw native module — bypasses JS-side input validation. Prefer using the named exports. */
export default AesModule
