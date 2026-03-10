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
        val hexArray = "0123456789abcdef".toCharArray()
        val hexChars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = hexArray[v ushr 4]
            hexChars[i * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }
}
