export const NativeModules = {
    Aes: {
        encrypt: jest.fn().mockResolvedValue('mockCipher'),
        decrypt: jest.fn().mockResolvedValue('mockPlain'),
        pbkdf2: jest.fn().mockResolvedValue('mockKey'),
        hmac256: jest.fn().mockResolvedValue('mockHmac'),
        hmac512: jest.fn().mockResolvedValue('mockHmac'),
        sha1: jest.fn().mockResolvedValue('mockHash'),
        sha256: jest.fn().mockResolvedValue('mockHash'),
        sha512: jest.fn().mockResolvedValue('mockHash'),
        encryptGcm: jest.fn().mockResolvedValue('mockGcmCipher'),
        decryptGcm: jest.fn().mockResolvedValue('mockGcmPlain'),
        randomUuid: jest.fn().mockResolvedValue('mock-uuid'),
        randomKey: jest.fn().mockResolvedValue('deadbeef'),
    },
}
