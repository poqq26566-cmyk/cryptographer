package com.example.cryptographer.infrastructure.security

import android.content.Context
import android.content.SharedPreferences
import com.example.cryptographer.infrastructure.persistence.KeystoreHelper
import dagger.hilt.android.qualifiers.ApplicationContext
import io.github.oshai.kotlinlogging.KotlinLogging
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Manages app lock password securely.
 * Uses Android Keystore to encrypt the stored hash at rest, and PBKDF2WithHmacSHA256
 * (salted, 210k iterations) to derive the password hash itself, so that even if the
 * stored value were ever recovered it would be resistant to brute-force / rainbow-table
 * attacks.
 */
@Singleton
class PasswordManager @Inject constructor(
    private val keystoreHelper: KeystoreHelper,
    @ApplicationContext private val context: Context,
) {
    private val logger = KotlinLogging.logger {}

    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    companion object {
        private const val PREFS_NAME = "app_lock_prefs"
        private const val KEY_PASSWORD_HASH = "password_hash"
        private const val KEY_PASSWORD_SALT = "password_salt"
        private const val KEY_BIOMETRIC_ENABLED = "biometric_enabled"
        private const val KEY_LOCK_ENABLED = "lock_enabled"

        private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
        private const val PBKDF2_ITERATIONS = 210_000 // OWASP-recommended minimum for PBKDF2-HMAC-SHA256
        private const val PBKDF2_KEY_LENGTH_BITS = 256
        private const val SALT_LENGTH_BYTES = 16
    }

    /**
     * Checks if app lock is enabled.
     */
    fun isLockEnabled(): Boolean {
        return prefs.getBoolean(KEY_LOCK_ENABLED, false)
    }

    /**
     * Enables app lock with a password.
     */
    fun setPassword(password: String): Result<Unit> {
        return try {
            val salt = generateSalt()
            val hash = hashPassword(password, salt)
            val encryptedHash = keystoreHelper.encrypt(hash)
            val encodedHash = android.util.Base64.encodeToString(encryptedHash, android.util.Base64.DEFAULT)
            val encodedSalt = android.util.Base64.encodeToString(salt, android.util.Base64.DEFAULT)

            prefs.edit()
                .putString(KEY_PASSWORD_HASH, encodedHash)
                .putString(KEY_PASSWORD_SALT, encodedSalt)
                .putBoolean(KEY_LOCK_ENABLED, true)
                .apply()

            logger.info { "Password set successfully" }
            Result.success(Unit)
        } catch (e: RuntimeException) {
            logger.error(e) { "Failed to set password" }
            Result.failure(e)
        } catch (e: java.security.GeneralSecurityException) {
            logger.error(e) { "Failed to set password: security error" }
            Result.failure(e)
        }
    }

    /**
     * Verifies if the provided password is correct.
     */
    fun verifyPassword(password: String): Boolean {
        return try {
            val encodedHash = prefs.getString(KEY_PASSWORD_HASH, null)
                ?: return false

            val encryptedHash = android.util.Base64.decode(encodedHash, android.util.Base64.DEFAULT)
            val storedHash = keystoreHelper.decrypt(encryptedHash)

            val encodedSalt = prefs.getString(KEY_PASSWORD_SALT, null)
            if (encodedSalt == null) {
                // Password was set before salted PBKDF2 hashing was introduced
                // (legacy unsalted SHA-256). Verify against the legacy scheme once,
                // and transparently migrate to the new scheme on success.
                val legacyHash = legacyHashPassword(password)
                if (!MessageDigest.isEqual(storedHash, legacyHash)) {
                    return false
                }
                logger.info { "Migrating legacy password hash to salted PBKDF2" }
                setPassword(password)
                return true
            }

            val salt = android.util.Base64.decode(encodedSalt, android.util.Base64.DEFAULT)
            val providedHash = hashPassword(password, salt)

            MessageDigest.isEqual(storedHash, providedHash)
        } catch (e: RuntimeException) {
            logger.error(e) { "Failed to verify password" }
            false
        } catch (e: java.security.GeneralSecurityException) {
            logger.error(e) { "Failed to verify password: security error" }
            false
        } catch (e: IllegalArgumentException) {
            logger.error(e) { "Failed to verify password: invalid argument" }
            false
        }
    }

    /**
     * Checks if password is set (app lock is configured).
     */
    fun hasPassword(): Boolean {
        return prefs.contains(KEY_PASSWORD_HASH) && isLockEnabled()
    }

    /**
     * Disables app lock and removes password.
     */
    fun removePassword() {
        prefs.edit()
            .remove(KEY_PASSWORD_HASH)
            .remove(KEY_PASSWORD_SALT)
            .putBoolean(KEY_LOCK_ENABLED, false)
            .putBoolean(KEY_BIOMETRIC_ENABLED, false)
            .apply()
        logger.info { "Password removed" }
    }

    /**
     * Enables or disables biometric authentication.
     */
    fun setBiometricEnabled(enabled: Boolean) {
        prefs.edit()
            .putBoolean(KEY_BIOMETRIC_ENABLED, enabled)
            .apply()
        logger.info { "Biometric enabled: $enabled" }
    }

    /**
     * Checks if biometric authentication is enabled.
     */
    fun isBiometricEnabled(): Boolean {
        return prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false)
    }

    /**
     * Derives a password hash using PBKDF2WithHmacSHA256 with the given salt.
     * 210,000 iterations makes brute-forcing significantly more expensive than a
     * single unsalted SHA-256 hash, and the per-password random salt defeats
     * precomputed rainbow-table attacks.
     */
    private fun hashPassword(password: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        return try {
            factory.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    /**
     * Generates a cryptographically secure random salt for PBKDF2.
     */
    private fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_LENGTH_BYTES)
        SecureRandom().nextBytes(salt)
        return salt
    }

    /**
     * Legacy unsalted SHA-256 hash, kept only to verify passwords that were set
     * before salted PBKDF2 hashing was introduced. Not used for any new password.
     */
    private fun legacyHashPassword(password: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(password.toByteArray(Charsets.UTF_8))
    }
}
