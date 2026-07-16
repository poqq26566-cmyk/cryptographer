package com.example.cryptographer.domain.text.services

import com.example.cryptographer.domain.common.errors.DomainError
import com.example.cryptographer.domain.common.services.DomainService
import com.example.cryptographer.domain.text.entities.EncryptedText
import com.example.cryptographer.domain.text.entities.EncryptionKey
import com.example.cryptographer.domain.text.entities.aes.AesGcmMode
import com.example.cryptographer.domain.text.entities.aes.AesKeyExpansion
import com.example.cryptographer.domain.text.entities.aes.AesRoundKeys
import com.example.cryptographer.domain.text.errors.UnsupportedAlgorithmError
import com.example.cryptographer.domain.text.valueobjects.EncryptionAlgorithm
import com.example.cryptographer.domain.text.valueobjects.aes.AesKeySize
import com.example.cryptographer.domain.text.valueobjects.aes.AesNumRounds
import io.github.oshai.kotlinlogging.KotlinLogging
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Domain service for AES encryption algorithm.
 * Supports AES-128, AES-192, and AES-256 with GCM mode.
 *
 * ✅ 优化说明：
 *   1. secureRandom 改为类成员变量复用，消除每次 encrypt() 构建 SecureRandom 的开销。
 *   2. roundKeyCache (ConcurrentHashMap) 缓存已扩展的 round key，
 *      同一把 key 的 AesKeyExpansion.expandKey() 只执行一次。
 *   3. encrypt() 和 buildKeyContext() 合并为统一的 getOrBuildKeyContext()，
 *      避免 encrypt 路径重复执行 validateKey / AesKeySize / AesNumRounds 构建。
 */
class AesEncryptionService : DomainService() {
    private val logger = KotlinLogging.logger {}

    // ✅ 优化 1：SecureRandom 复用（线程安全），消除每次 encrypt 的实例化开销
    private val secureRandom = SecureRandom()

    // ✅ 优化 2：round key 缓存，key = "算法名_keyHex"，同一把 key 只扩展一次
    private val roundKeyCache = ConcurrentHashMap<String, KeyContext>()

    companion object {
        private const val GCM_TAG_LENGTH = 16 // bytes (128 bits)
        private const val GCM_IV_LENGTH = 12 // bytes (96 bits)
        private const val BITS_IN_BYTE = 8

        // AES key sizes in bytes
        private const val AES_128_KEY_SIZE_BYTES = 16 // 128 bits = 16 bytes
        private const val AES_192_KEY_SIZE_BYTES = 24 // 192 bits = 24 bytes
        private const val AES_256_KEY_SIZE_BYTES = 32 // 256 bits = 32 bytes
    }

    private data class KeyContext(
        val roundKeys: AesRoundKeys,
        val numRounds: AesNumRounds,
    )

    private data class CiphertextAndTag(
        val ciphertext: ByteArray,
        val tag: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as CiphertextAndTag
            if (!ciphertext.contentEquals(other.ciphertext)) return false
            if (!tag.contentEquals(other.tag)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = ciphertext.contentHashCode()
            result = 31 * result + tag.contentHashCode()
            return result
        }
    }

    private val emptyAad = ByteArray(0)

    /**
     * Encrypts data using the provided AES key with GCM mode.
     *
     * @param data Data to encrypt
     * @param key AES encryption key
     * @return Result with encrypted data or error
     */
    fun encrypt(data: ByteArray, key: EncryptionKey): Result<EncryptedText> {
        return try {
            logger.info { "Starting AES encryption: algorithm=${key.algorithm}, dataSize=${data.size} bytes" }

            // ✅ 优化 2：从缓存获取或构建 KeyContext，相同 key 只扩展一次
            val keyContext = getOrBuildKeyContext(key)

            // ✅ 优化 1：复用 secureRandom 实例
            val iv = ByteArray(GCM_IV_LENGTH)
            secureRandom.nextBytes(iv)

            val (ciphertext, tag) = AesGcmMode.encrypt(
                AesGcmMode.EncryptParams(
                    plaintext = data,
                    iv = iv,
                    aad = emptyAad,
                    roundKeys = keyContext.roundKeys,
                    numRounds = keyContext.numRounds,
                ),
            )

            // Combine ciphertext and tag: encryptedData = ciphertext || tag
            val encryptedData = ByteArray(ciphertext.size + tag.size)
            System.arraycopy(ciphertext, 0, encryptedData, 0, ciphertext.size)
            System.arraycopy(tag, 0, encryptedData, ciphertext.size, tag.size)

            logger.info {
                "AES encryption completed successfully: algorithm=${key.algorithm}, " +
                    "plaintextSize=${data.size} bytes, " +
                    "encryptedSize=${encryptedData.size} bytes, " +
                    "ciphertextSize=${ciphertext.size} bytes, " +
                    "tagSize=${tag.size} bytes, " +
                    "ivSize=${iv.size} bytes"
            }
            Result.success(
                EncryptedText(
                    encryptedData = encryptedData,
                    algorithm = key.algorithm,
                    initializationVector = iv,
                ),
            )
        } catch (e: UnsupportedAlgorithmError) {
            logger.error(e) { "Encryption failed: unsupported algorithm=${key.algorithm}" }
            Result.failure(e)
        } catch (e: DomainError) {
            logger.error(e) { "Encryption failed: algorithm=${key.algorithm}, error=${e.message}" }
            Result.failure(e)
        }
    }

    /**
     * Decrypts data using the provided AES key and verifies GCM authentication tag.
     *
     * @param encryptedText Encrypted data (ciphertext || tag) with IV
     * @param key AES encryption key
     * @return Result with decrypted data or error if authentication fails
     */
    fun decrypt(encryptedText: EncryptedText, key: EncryptionKey): Result<ByteArray> {
        return try {
            logger.info {
                "Starting AES decryption: " +
                    "algorithm=${key.algorithm}, " +
                    "encryptedSize=${encryptedText.encryptedData.size} bytes"
            }

            val iv = requireInitializationVector(encryptedText)
            val encryptedData = encryptedText.encryptedData
            requireEncryptedDataLength(encryptedData)

            // ✅ 优化 2：从缓存获取或构建 KeyContext
            val keyContext = getOrBuildKeyContext(key)
            val (ciphertext, tag) = splitCiphertextAndTag(encryptedData)

            val decryptedData = decryptAndVerify(ciphertext, tag, iv, emptyAad, keyContext)

            logger.info {
                "AES decryption completed successfully: algorithm=${key.algorithm}, " +
                    "encryptedSize=${encryptedData.size} bytes, " +
                    "ciphertextSize=${ciphertext.size} bytes, " +
                    "tagSize=${tag.size} bytes, " +
                    "decryptedSize=${decryptedData.size} bytes"
            }
            Result.success(decryptedData)
        } catch (e: UnsupportedAlgorithmError) {
            logger.error(e) { "Decryption failed: unsupported algorithm=${key.algorithm}" }
            Result.failure(e)
        } catch (e: DomainError) {
            logger.error(e) { "Decryption failed: algorithm=${key.algorithm}, error=${e.message}" }
            Result.failure(e)
        }
    }

    /**
     * Generates a new AES encryption key for the specified algorithm.
     *
     * @param algorithm AES algorithm (AES_128, AES_192, AES_256)
     * @return Result with generated key or error
     */
    fun generateKey(algorithm: EncryptionAlgorithm): Result<EncryptionKey> {
        return try {
            logger.info { "Starting AES key generation: algorithm=$algorithm" }

            val keySizeBytes = when (algorithm) {
                EncryptionAlgorithm.AES_128 -> AES_128_KEY_SIZE_BYTES
                EncryptionAlgorithm.AES_192 -> AES_192_KEY_SIZE_BYTES
                EncryptionAlgorithm.AES_256 -> AES_256_KEY_SIZE_BYTES
                else -> throw UnsupportedAlgorithmError(algorithm, "AesEncryptionService")
            }

            // ✅ 优化 1：复用 secureRandom 实例生成密钥
            val keyBytes = ByteArray(keySizeBytes)
            secureRandom.nextBytes(keyBytes)

            logger.info {
                "AES key generation completed successfully: algorithm=$algorithm, " +
                    "keySize=${keyBytes.size} bytes (${keyBytes.size * BITS_IN_BYTE} bits)"
            }
            Result.success(
                EncryptionKey(
                    value = keyBytes,
                    algorithm = algorithm,
                ),
            )
        } catch (e: UnsupportedAlgorithmError) {
            logger.error(e) { "Key generation failed: unsupported algorithm=$algorithm" }
            Result.failure(e)
        } catch (e: DomainError) {
            logger.error(e) { "Key generation failed: algorithm=$algorithm, error=${e.message}" }
            Result.failure(e)
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────

    /**
     * ✅ 优化 2：从缓存获取已扩展的 KeyContext，未命中时构建并缓存。
     *
     * 缓存键格式："算法名_keyHex"，既区分算法又区分 key 内容，
     * 使用 hex 字符串而非 ByteArray 作为 Map key 以保证哈希正确性。
     */
    private fun getOrBuildKeyContext(key: EncryptionKey): KeyContext {
        val cacheKey = buildCacheKey(key)
        return roundKeyCache.getOrPut(cacheKey) {
            logger.debug { "KeyContext cache miss, building: algorithm=${key.algorithm}" }
            buildKeyContext(key)
        }
    }

    /**
     * 构建缓存 key：算法名 + "_" + key 字节的十六进制字符串。
     */
    private fun buildCacheKey(key: EncryptionKey): String {
        val hex = key.value.joinToString("") { "%02x".format(it) }
        return "${key.algorithm.name}_$hex"
    }

    private fun buildKeyContext(key: EncryptionKey): KeyContext {
        validateKey(key)

        val keySize = AesKeySize.create(key.algorithm).getOrElse {
            throw UnsupportedAlgorithmError(key.algorithm, "AesEncryptionService")
        }
        val numRounds = AesNumRounds.create(key.algorithm).getOrElse {
            throw UnsupportedAlgorithmError(key.algorithm, "AesEncryptionService")
        }

        keySize.validateKeyBytes(key.value).getOrThrow()

        val roundKeys = AesKeyExpansion.expandKey(key.value, numRounds)
        logger.debug { "Key expansion completed: generated ${roundKeys.roundKeys.size} round keys" }

        return KeyContext(roundKeys = roundKeys, numRounds = numRounds)
    }

    private fun requireInitializationVector(encryptedText: EncryptedText): ByteArray {
        val iv = encryptedText.initializationVector
        if (iv == null) {
            logger.warn { "Decryption failed: IV is missing" }
            throw DomainError("IV (Initialization Vector) is missing for decryption")
        }
        return iv
    }

    private fun requireEncryptedDataLength(encryptedData: ByteArray) {
        if (encryptedData.size < GCM_TAG_LENGTH) {
            logger.warn {
                "Decryption failed: encrypted data too short, " +
                    "size=${encryptedData.size}, " +
                    "expected at least $GCM_TAG_LENGTH bytes"
            }
            throw DomainError(
                "Encrypted data is too short. " +
                    "Minimum size is $GCM_TAG_LENGTH bytes for tag",
            )
        }
    }

    private fun splitCiphertextAndTag(encryptedData: ByteArray): CiphertextAndTag {
        val ciphertextSize = encryptedData.size - GCM_TAG_LENGTH
        val ciphertext = ByteArray(ciphertextSize)
        val tag = ByteArray(GCM_TAG_LENGTH)
        System.arraycopy(encryptedData, 0, ciphertext, 0, ciphertextSize)
        System.arraycopy(encryptedData, ciphertextSize, tag, 0, GCM_TAG_LENGTH)
        return CiphertextAndTag(ciphertext = ciphertext, tag = tag)
    }

    private fun decryptAndVerify(
        ciphertext: ByteArray,
        tag: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        keyContext: KeyContext,
    ): ByteArray {
        val decryptedData = AesGcmMode.decrypt(
            AesGcmMode.DecryptParams(
                ciphertext = ciphertext,
                tag = tag,
                iv = iv,
                aad = aad,
                roundKeys = keyContext.roundKeys,
                numRounds = keyContext.numRounds,
            ),
        )
        if (decryptedData == null) {
            logger.warn { "Decryption failed: authentication tag verification failed - data may have been tampered with" }
            throw DomainError("Authentication failed: invalid tag. The data may have been tampered with.")
        }
        return decryptedData
    }

    /**
     * Validates that the key matches the expected length for its algorithm.
     */
    private fun validateKey(key: EncryptionKey) {
        val expectedKeyLength = when (key.algorithm) {
            EncryptionAlgorithm.AES_128 -> AES_128_KEY_SIZE_BYTES
            EncryptionAlgorithm.AES_192 -> AES_192_KEY_SIZE_BYTES
            EncryptionAlgorithm.AES_256 -> AES_256_KEY_SIZE_BYTES
            else -> throw UnsupportedAlgorithmError(key.algorithm, "AesEncryptionService")
        }

        if (key.value.size != expectedKeyLength) {
            throw DomainError(
                "Invalid key length. Expected $expectedKeyLength bytes, got ${key.value.size} bytes",
            )
        }
    }
}
