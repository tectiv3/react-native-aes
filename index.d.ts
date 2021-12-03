declare module 'react-native-aes-crypto' {
    namespace Aes {
        type Algorithms = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc'

        function pbkdf2(password: string, salt: string, cost: number, length: number): Promise<string>
        function encrypt(text: string, key: string, iv: string, algorithm: Algorithms): Promise<string>
        function decrypt(ciphertext: string, key: string, iv: string, algorithm: Algorithms): Promise<string>
        function hmac256(ciphertext: string, key: string): Promise<string>
        function hmac512(ciphertext: string, key: string): Promise<string>
        function randomKey(length: number): Promise<string>
        function sha1(text: string): Promise<string>
        function sha256(text: string): Promise<string>
        function sha512(text: string): Promise<string>
    }
}
