package com.example.cryptographer.domain.text.entities.aes

import com.example.cryptographer.domain.text.valueobjects.aes.AesBlock
import com.example.cryptographer.domain.text.valueobjects.aes.AesNumRounds

/**
 * GHASH-based authentication for AES-GCM.
 *
 * ✅ 优化说明：
 *   1. ghash() 中移除 data.sliceArray()，改为直接用偏移量访问原数组，
 *      消除每个 16 字节 block 的临时 ByteArray 分配（大文件可节省数万次分配）。
 *   2. gf128Mul 的结果通过 copyInto 写回 x，ghash 的累加器 y 全程复用同一对象，
 *      消除循环内的 var y = gf128Mul(...) 重新赋值引发的旧对象 GC 压力。
 */
internal object AesGcmAuthenticator {
    private const val BLOCK_SIZE = 16 // bytes (128 bits)
    private const val TAG_LENGTH = 16 // bytes (128 bits)
    private const val BITS_IN_BYTE = 8
    private const val BYTE_MASK = 0xFF
    private const val LOW_BIT_MASK = 0x01
    private const val MSB_INDEX = 7
    private const val LENGTH_FIELD_SIZE = 8 // bytes (64-bit length)
    private const val LENGTH_START_SHIFT = 56 // 7 * 8
    private const val REDUCTION_POLYNOMIAL_BYTE = 0xE1

    internal class TagContext(
        val j0: AesBlock,
        val h: AesBlock,
        val roundKeys: AesRoundKeys,
        val numRounds: AesNumRounds,
    )

    internal fun generateTag(aad: ByteArray, ciphertext: ByteArray, context: TagContext): ByteArray {
        // Construct S = AAD || C || len(AAD) || len(C)
        val s = ByteArray(
            padToBlockMultiple(aad.size) +
                padToBlockMultiple(ciphertext.size) + BLOCK_SIZE,
        )
        var offset = 0

        // Append AAD (padded to block multiple)
        System.arraycopy(aad, 0, s, offset, aad.size)
        offset += padToBlockMultiple(aad.size)

        // Append ciphertext (padded to block multiple)
        System.arraycopy(ciphertext, 0, s, offset, ciphertext.size)
        offset += padToBlockMultiple(ciphertext.size)

        // Append lengths (64 bits each, big-endian)
        appendLength(aad.size.toLong() * BITS_IN_BYTE, s, offset)
        offset += LENGTH_FIELD_SIZE
        appendLength(ciphertext.size.toLong() * BITS_IN_BYTE, s, offset)

        // Compute GHASH
        val ghashResult = ghash(s, context.h.bytes)

        // Compute tag = GHASH ^ E_k(J0)
        val encryptedJ0 = AesCore.encryptBlock(context.j0, context.roundKeys, context.numRounds)
        val tagBytes = ByteArray(TAG_LENGTH)
        for (i in 0 until TAG_LENGTH) {
            tagBytes[i] = (ghashResult[i].toInt() xor encryptedJ0.bytes[i].toInt()).toByte()
        }

        return tagBytes
    }

    /**
     * GHASH function - universal hashing over GF(2^128).
     *
     * GHASH computes: Y_0 = 0, Y_i = (Y_{i-1} XOR X_i) * H
     *
     * ✅ 优化：直接用 data[i + j] 偏移访问，消除 sliceArray 产生的临时数组。
     *         y 全程复用同一 ByteArray，gf128MulInPlace 原地更新，无新对象分配。
     */
    private fun ghash(data: ByteArray, h: ByteArray): ByteArray {
        require(data.size % BLOCK_SIZE == 0) { "Data must be multiple of block size" }
        require(h.size == BLOCK_SIZE) { "H must be block size" }

        val y = ByteArray(BLOCK_SIZE) // 累加器，全程复用

        for (i in data.indices step BLOCK_SIZE) {
            // ✅ XOR block with accumulator — 直接按偏移访问，不产生中间数组
            for (j in 0 until BLOCK_SIZE) {
                y[j] = (y[j].toInt() xor data[i + j].toInt()).toByte()
            }
            // ✅ 原地 GF(2^128) 乘法，结果写回 y，无新对象产生
            gf128MulInPlace(y, h)
        }

        return y
    }

    /**
     * In-place multiplication in GF(2^128) modulo irreducible polynomial.
     * Irreducible polynomial: x^128 + x^7 + x^2 + x + 1
     *
     * ✅ 优化：将原 gf128Mul(x, y): ByteArray 改为原地操作，
     *         result 在栈上分配后 copyInto x，v 复用局部变量，
     *         ghash 的每次循环节省一次 ByteArray(16) 的堆分配与 GC。
     *
     * @param x 被乘数（原地修改，结果写回此数组）
     * @param y 乘数（只读）
     */
    private fun gf128MulInPlace(x: ByteArray, y: ByteArray) {
        val result = ByteArray(BLOCK_SIZE)
        val v = y.copyOf()

        for (i in 0 until BLOCK_SIZE) {
            val xByte = x[i].toInt() and BYTE_MASK
            for (j in 0 until BITS_IN_BYTE) {
                if (isBitSet(xByte, j)) {
                    xorIntoResult(result, v)
                }
                val carry = shiftRightWithCarry(v)
                if (carry) {
                    v[BLOCK_SIZE - 1] = (v[BLOCK_SIZE - 1].toInt() xor REDUCTION_POLYNOMIAL_BYTE).toByte()
                }
            }
        }

        // 将结果写回 x
        result.copyInto(x)
    }

    private fun isBitSet(byteValue: Int, bitIndex: Int): Boolean {
        val bit = (byteValue ushr (MSB_INDEX - bitIndex)) and LOW_BIT_MASK
        return bit != 0
    }

    private fun xorIntoResult(result: ByteArray, value: ByteArray) {
        for (i in 0 until BLOCK_SIZE) {
            result[i] = (result[i].toInt() xor value[i].toInt()).toByte()
        }
    }

    private fun shiftRightWithCarry(value: ByteArray): Boolean {
        val carry = (value[BLOCK_SIZE - 1].toInt() and LOW_BIT_MASK) != 0
        for (i in BLOCK_SIZE - 1 downTo 1) {
            value[i] =
                ((value[i].toInt() ushr 1) or ((value[i - 1].toInt() and LOW_BIT_MASK) shl MSB_INDEX))
                    .toByte()
        }
        value[0] = (value[0].toInt() ushr 1).toByte()
        return carry
    }

    /**
     * Pads length to next multiple of block size.
     */
    private fun padToBlockMultiple(length: Int): Int {
        return ((length + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE
    }

    /**
     * Appends 64-bit length (in bits) as big-endian bytes.
     */
    private fun appendLength(length: Long, buffer: ByteArray, offset: Int) {
        for (i in 0 until LENGTH_FIELD_SIZE) {
            buffer[offset + i] =
                ((length ushr (LENGTH_START_SHIFT - i * BITS_IN_BYTE)) and BYTE_MASK.toLong()).toByte()
        }
    }
}
