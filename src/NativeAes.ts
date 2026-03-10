import type { TurboModule } from 'react-native'
import { TurboModuleRegistry } from 'react-native'

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
