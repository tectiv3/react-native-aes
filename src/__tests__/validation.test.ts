import { encrypt, decrypt, pbkdf2, hmac256, hmac512, randomKey, encryptGcm, decryptGcm } from '../index'

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
        expect(() => encrypt('data', 'key', 'iv', 'aes-256-ecb' as any)).toThrow(
            'Unsupported algorithm'
        )
    })

    it('rejects empty ciphertext for decrypt', () => {
        expect(() => decrypt('', 'key', 'iv', 'aes-256-cbc')).toThrow(
            'ciphertext must not be empty'
        )
    })

    it('rejects pbkdf2 with low length', () => {
        expect(() => pbkdf2('pass', 'salt', 1000, 64, 'sha256')).toThrow('at least 128')
    })

    it('rejects pbkdf2 with zero cost', () => {
        expect(() => pbkdf2('pass', 'salt', 0, 256, 'sha256')).toThrow('positive integer')
    })

    it('rejects pbkdf2 with invalid algorithm', () => {
        expect(() => pbkdf2('pass', 'salt', 1000, 256, 'md5' as any)).toThrow(
            'Unsupported algorithm'
        )
    })

    it('rejects randomKey with zero length', () => {
        expect(() => randomKey(0)).toThrow('positive integer')
    })

    it('rejects hmac256 with empty data', () => {
        expect(() => hmac256('', 'key')).toThrow('data must not be empty')
    })

    it('rejects hmac512 with empty key', () => {
        expect(() => hmac512('data', '')).toThrow('key must not be empty')
    })

    it('rejects encryptGcm with invalid tag length', () => {
        expect(() => encryptGcm('data', 'key', 'iv', '', 64)).toThrow('tagLength must be')
    })

    it('rejects decryptGcm with empty key', () => {
        expect(() => decryptGcm('data', '', 'iv')).toThrow('key must not be empty')
    })

    it('accepts valid encrypt call', async () => {
        const result = await encrypt('hello', 'key', 'iv', 'aes-256-cbc')
        expect(result).toBe('mockCipher')
    })

    it('accepts valid pbkdf2 call', async () => {
        const result = await pbkdf2('pass', 'salt', 1000, 256, 'sha256')
        expect(result).toBe('mockKey')
    })

    it('accepts valid encryptGcm call', async () => {
        const result = await encryptGcm('hello', 'key', 'iv')
        expect(result).toBe('mockGcmCipher')
    })
})
