import { NativeModules } from 'react-native'
import {
    encrypt,
    decrypt,
    pbkdf2,
    hmac256,
    hmac512,
    sha1,
    sha256,
    sha512,
    encryptGcm,
    decryptGcm,
    randomKey,
    randomUuid,
} from '../index'

const native = NativeModules.Aes

beforeEach(() => {
    jest.clearAllMocks()
})

describe('README example: encrypt/decrypt with PBKDF2', () => {
    it('derives a key, encrypts, decrypts, and computes HMAC', async () => {
        const hexKey = 'aa'.repeat(32)
        const hexIv = 'bb'.repeat(16)
        native.pbkdf2.mockResolvedValueOnce(hexKey)
        native.randomKey.mockResolvedValueOnce(hexIv)

        const key = await pbkdf2('password', 'salt', 100000, 256, 'sha256')
        expect(native.pbkdf2).toHaveBeenCalledWith('password', 'salt', 100000, 256, 'sha256')
        expect(key).toBe(hexKey)

        const iv = await randomKey(16)
        expect(native.randomKey).toHaveBeenCalledWith(16)
        expect(iv).toBe(hexIv)

        const cipher = await encrypt('Hello, World!', key, iv, 'aes-256-cbc')
        expect(native.encrypt).toHaveBeenCalledWith('Hello, World!', key, iv, 'aes-256-cbc')
        expect(cipher).toBe('mockCipher')

        const plaintext = await decrypt(cipher, key, iv, 'aes-256-cbc')
        expect(native.decrypt).toHaveBeenCalledWith(cipher, key, iv, 'aes-256-cbc')
        expect(plaintext).toBe('mockPlain')

        const hash = await hmac256(cipher, key)
        expect(native.hmac256).toHaveBeenCalledWith(cipher, key)
        expect(hash).toBe('mockHmac')
    })
})

describe('AES-CBC with all key sizes', () => {
    const iv = 'abcdef0123456789abcdef0123456789'

    it.each([
        ['aes-128-cbc', 'a'.repeat(32)],
        ['aes-192-cbc', 'b'.repeat(48)],
        ['aes-256-cbc', 'c'.repeat(64)],
    ] as const)('encrypts and decrypts with %s', async (algorithm, key) => {
        await encrypt('test data', key, iv, algorithm as any)
        expect(native.encrypt).toHaveBeenCalledWith('test data', key, iv, algorithm)

        await decrypt('mockCipher', key, iv, algorithm as any)
        expect(native.decrypt).toHaveBeenCalledWith('mockCipher', key, iv, algorithm)
    })
})

describe('AES-CTR with all key sizes', () => {
    const iv = '00112233445566778899aabbccddeeff'

    it.each([
        ['aes-128-ctr', 'a'.repeat(32)],
        ['aes-192-ctr', 'b'.repeat(48)],
        ['aes-256-ctr', 'c'.repeat(64)],
    ] as const)('encrypts and decrypts with %s', async (algorithm, key) => {
        await encrypt('stream cipher test', key, iv, algorithm as any)
        expect(native.encrypt).toHaveBeenCalledWith('stream cipher test', key, iv, algorithm)

        await decrypt('mockCipher', key, iv, algorithm as any)
        expect(native.decrypt).toHaveBeenCalledWith('mockCipher', key, iv, algorithm)
    })
})

describe('AES-GCM authenticated encryption', () => {
    const key = 'aa'.repeat(16)
    const iv = 'bb'.repeat(12)

    it('encrypts and decrypts with defaults (no AAD, 128-bit tag)', async () => {
        const cipher = await encryptGcm('secret', key, iv)
        expect(native.encryptGcm).toHaveBeenCalledWith('secret', key, iv, '', 128)

        await decryptGcm(cipher, key, iv)
        expect(native.decryptGcm).toHaveBeenCalledWith(cipher, key, iv, '', 128)
    })

    it('encrypts with AAD and custom tag length', async () => {
        await encryptGcm('secret', key, iv, 'additional-data', 96)
        expect(native.encryptGcm).toHaveBeenCalledWith('secret', key, iv, 'additional-data', 96)

        await decryptGcm('mockGcmCipher', key, iv, 'additional-data', 96)
        expect(native.decryptGcm).toHaveBeenCalledWith('mockGcmCipher', key, iv, 'additional-data', 96)
    })
})

describe('PBKDF2 with all hash algorithms', () => {
    it.each(['sha1', 'sha256', 'sha512'] as const)(
        'derives key with %s',
        async (algorithm) => {
            const result = await pbkdf2('mypassword', 'randomsalt', 10000, 256, algorithm)
            expect(native.pbkdf2).toHaveBeenCalledWith(
                'mypassword',
                'randomsalt',
                10000,
                256,
                algorithm
            )
            expect(result).toBe('mockKey')
        }
    )
})

describe('HMAC', () => {
    const hexKey = 'deadbeefcafebabe'

    it('computes HMAC-SHA256', async () => {
        const result = await hmac256('message to authenticate', hexKey)
        expect(native.hmac256).toHaveBeenCalledWith('message to authenticate', hexKey)
        expect(result).toBe('mockHmac')
    })

    it('computes HMAC-SHA512', async () => {
        const result = await hmac512('message to authenticate', hexKey)
        expect(native.hmac512).toHaveBeenCalledWith('message to authenticate', hexKey)
        expect(result).toBe('mockHmac')
    })
})

describe('hash functions', () => {
    it('computes SHA-1', async () => {
        const result = await sha1('hello')
        expect(native.sha1).toHaveBeenCalledWith('hello')
        expect(result).toBe('mockHash')
    })

    it('computes SHA-256', async () => {
        const result = await sha256('hello')
        expect(native.sha256).toHaveBeenCalledWith('hello')
        expect(result).toBe('mockHash')
    })

    it('computes SHA-512', async () => {
        const result = await sha512('hello')
        expect(native.sha512).toHaveBeenCalledWith('hello')
        expect(result).toBe('mockHash')
    })
})

describe('utilities', () => {
    it('generates a random UUID', async () => {
        const result = await randomUuid()
        expect(native.randomUuid).toHaveBeenCalled()
        expect(result).toBe('mock-uuid')
    })

    it('generates random bytes as hex', async () => {
        const result = await randomKey(32)
        expect(native.randomKey).toHaveBeenCalledWith(32)
        expect(result).toBe('deadbeef')
    })
})
