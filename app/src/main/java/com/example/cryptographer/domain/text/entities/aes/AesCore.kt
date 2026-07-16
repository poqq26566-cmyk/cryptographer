package com.example.cryptographer.domain.text.entities.aes

import com.example.cryptographer.domain.text.valueobjects.aes.AesBlock
import com.example.cryptographer.domain.text.valueobjects.aes.AesNumRounds
import com.example.cryptographer.domain.text.valueobjects.aes.AesSBox
import com.example.cryptographer.domain.text.valueobjects.aes.AesState

/**
 * Core AES (Advanced Encryption Standard) implementation.
 *
 * Implements AES block encryption/decryption operations:
 * - SubBytes: Non-linear substitution using S-box
 * - ShiftRows: Cyclic shift of rows
 * - MixColumns: Linear transformation of columns
 * - AddRoundKey: XOR with round key
 *
 * AES operates on 128-bit blocks with keys of 128, 192, or 256 bits.
 * This follows the Rijndael algorithm specification (FIPS 197).
 *
 * ✅ 优化说明：
 *   1. 移除所有热路径中的 logger.trace 调用，消除循环内的 lambda 构建开销。
 *   2. MixColumns 使用预计算查找表（MUL2 / MUL3）替代逐 bit 循环的 gfMul，
 *      将每次乘法从 O(8) 循环降为 O(1) 数组查找。
 *   3. AesState 已改为原地操作，encryptBlock 全程零额外矩阵复制。
 */
internal object AesCore {
    private const val STATE_ROWS = 4
    private const val STATE_COLS = 4
    private const val BYTE_MASK = 0xFF
    private const val INDEX_0 = 0
    private const val INDEX_1 = 1
    private const val INDEX_2 = 2
    private const val INDEX_3 = 3

    // ✅ 预计算 GF(2^8) 乘法查找表，避免 gfMul 中每次 8 次循环迭代
    // MUL2[b] = b * 0x02 mod 0x11B
    private val MUL2 = IntArray(256) { b ->
        val shifted = b shl 1
        if (b and 0x80 != 0) (shifted xor 0x1B) and 0xFF else shifted and 0xFF
    }

    // MUL3[b] = b * 0x03 mod 0x11B = MUL2[b] XOR b
    private val MUL3 = IntArray(256) { b -> MUL2[b] xor b }

    /**
     * Encrypts a single 128-bit block using AES.
     *
     * @param block AES block to encrypt
     * @param roundKeys Round keys entity
     * @param numRounds Number of rounds value object
     * @return Encrypted AES block
     */
    fun encryptBlock(block: AesBlock, roundKeys: AesRoundKeys, numRounds: AesNumRounds): AesBlock {
        require(roundKeys.numRounds == numRounds.rounds) {
            "Round keys rounds (${roundKeys.numRounds}) must match numRounds (${numRounds.rounds})"
        }

        // ✅ AesState.fromBlock 现在直接 copyOf，无二维数组构建开销
        val state = AesState.fromBlock(block.bytes)

        // Initial AddRoundKey
        addRoundKey(state, roundKeys.getInitialRoundKey().bytes)

        // Main rounds — ✅ 已移除循环内 logger.trace，消除热路径 lambda 开销
        for (round in 1 until numRounds.rounds) {
            subBytes(state)
            shiftRows(state)
            mixColumns(state)
            addRoundKey(state, roundKeys.getRoundKey(round).bytes)
        }

        // Final round (no MixColumns)
        subBytes(state)
        shiftRows(state)
        addRoundKey(state, roundKeys.getFinalRoundKey().bytes)

        // ✅ AesState.toBlock 现在直接 copyOf 扁平数组，无逐字节转换
        return AesBlock.create(state.toBlock()).getOrThrow()
    }

    /**
     * SubBytes transformation - non-linear byte substitution using S-box.
     * ✅ 优化：AesState.setByte 现在原地修改，不再复制矩阵。
     */
    private fun subBytes(state: AesState) {
        for (i in 0 until STATE_ROWS) {
            for (j in 0 until STATE_COLS) {
                val value = state.getByte(i, j).toInt() and BYTE_MASK
                state.setByte(i, j, AesSBox.getSBox(value))
            }
        }
    }

    /**
     * ShiftRows transformation - cyclic left shift of rows.
     * Row 0: no shift, Row 1: 1 byte, Row 2: 2 bytes, Row 3: 3 bytes.
     * ✅ 优化：AesState.setRow 现在原地修改，不再复制矩阵。
     */
    private fun shiftRows(state: AesState) {
        // Row 0: no shift

        // Row 1: shift left by 1
        val row1 = state.getRow(INDEX_1)
        state.setRow(INDEX_1, byteArrayOf(row1[INDEX_1], row1[INDEX_2], row1[INDEX_3], row1[INDEX_0]))

        // Row 2: shift left by 2
        val row2 = state.getRow(INDEX_2)
        state.setRow(INDEX_2, byteArrayOf(row2[INDEX_2], row2[INDEX_3], row2[INDEX_0], row2[INDEX_1]))

        // Row 3: shift left by 3 (= shift right by 1)
        val row3 = state.getRow(INDEX_3)
        state.setRow(INDEX_3, byteArrayOf(row3[INDEX_3], row3[INDEX_0], row3[INDEX_1], row3[INDEX_2]))
    }

    /**
     * MixColumns transformation - multiplication of each column by a fixed matrix in GF(2^8).
     * ✅ 优化：使用 MUL2/MUL3 查找表替代 gfMul 循环，O(1) 完成每次乘法。
     *         AesState.setColumn 原地修改，不再复制矩阵。
     */
    private fun mixColumns(state: AesState) {
        for (c in 0 until STATE_COLS) {
            val column = state.getColumn(c)
            val s0 = column[INDEX_0].toInt() and BYTE_MASK
            val s1 = column[INDEX_1].toInt() and BYTE_MASK
            val s2 = column[INDEX_2].toInt() and BYTE_MASK
            val s3 = column[INDEX_3].toInt() and BYTE_MASK

            state.setColumn(
                c,
                byteArrayOf(
                    (MUL2[s0] xor MUL3[s1] xor s2 xor s3).toByte(),
                    (s0 xor MUL2[s1] xor MUL3[s2] xor s3).toByte(),
                    (s0 xor s1 xor MUL2[s2] xor MUL3[s3]).toByte(),
                    (MUL3[s0] xor s1 xor s2 xor MUL2[s3]).toByte(),
                ),
            )
        }
    }

    /**
     * AddRoundKey transformation - XOR state with round key.
     * ✅ 优化：AesState.setByte 原地修改，不再复制矩阵。
     */
    private fun addRoundKey(state: AesState, roundKey: ByteArray) {
        for (c in 0 until STATE_COLS) {
            for (r in 0 until STATE_ROWS) {
                val currentByte = state.getByte(r, c).toInt() and BYTE_MASK
                val keyByte = roundKey[r + STATE_ROWS * c].toInt() and BYTE_MASK
                state.setByte(r, c, (currentByte xor keyByte).toByte())
            }
        }
    }
}
