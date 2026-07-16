package com.example.cryptographer.domain.text.valueobjects.aes

import com.example.cryptographer.domain.common.values.BaseValueObject

/**
 * Value Object for AES state matrix (4x4 bytes = 16 bytes = 128 bits).
 *
 * Represents the internal state of AES during encryption/decryption.
 * AES state is a 4x4 matrix of bytes in column-major order.
 *
 * ✅ 优化：改用 16 字节扁平 ByteArray 存储，setByte/setRow/setColumn
 *    均原地修改并返回 this，消除原实现中每次操作都全量复制矩阵的开销。
 *
 * This is a Value Object following DDD principles - it's immutable externally.
 */
class AesState private constructor(
    // 扁平列主序数组：index = row + 4 * col
    private val data: ByteArray,
) : BaseValueObject() {

    companion object {
        private const val STATE_ROWS = 4
        private const val STATE_COLS = 4
        private const val BLOCK_SIZE = 16 // bytes (128 bits)

        /**
         * Creates AES state from block bytes (column-major order).
         *
         * @param block 16-byte block
         * @return AesState
         */
        fun fromBlock(block: ByteArray): AesState {
            require(block.size == BLOCK_SIZE) { "Block must be $BLOCK_SIZE bytes" }
            // 列主序与原始 block 布局完全一致，直接 copyOf 即可
            return AesState(block.copyOf())
        }
    }

    /**
     * Gets byte at specified position (row, column).
     * 列主序：index = row + 4 * col
     */
    fun getByte(row: Int, col: Int): Byte {
        require(row in 0 until STATE_ROWS && col in 0 until STATE_COLS) {
            "Invalid position: row=$row, col=$col"
        }
        return data[row + STATE_ROWS * col]
    }

    /**
     * Gets entire row as byte array.
     * ✅ 优化：不再需要从二维数组聚合，直接按步长读取扁平数组。
     */
    fun getRow(row: Int): ByteArray {
        require(row in 0 until STATE_ROWS) { "Invalid row: $row" }
        return byteArrayOf(
            data[row],
            data[row + STATE_ROWS],
            data[row + STATE_ROWS * 2],
            data[row + STATE_ROWS * 3],
        )
    }

    /**
     * Gets entire column as byte array.
     * ✅ 优化：列在扁平数组中是连续的 4 字节，直接 copyOfRange。
     */
    fun getColumn(col: Int): ByteArray {
        require(col in 0 until STATE_COLS) { "Invalid column: $col" }
        val base = col * STATE_ROWS
        return data.copyOfRange(base, base + STATE_ROWS)
    }

    /**
     * Sets byte at specified position.
     * ✅ 优化：原地修改，不再每次复制整个矩阵，返回 this 保持链式调用兼容性。
     */
    fun setByte(row: Int, col: Int, value: Byte): AesState {
        require(row in 0 until STATE_ROWS && col in 0 until STATE_COLS) {
            "Invalid position: row=$row, col=$col"
        }
        data[row + STATE_ROWS * col] = value
        return this
    }

    /**
     * Sets entire row.
     * ✅ 优化：原地修改，按步长写入扁平数组。
     */
    fun setRow(row: Int, values: ByteArray): AesState {
        require(row in 0 until STATE_ROWS) { "Invalid row: $row" }
        require(values.size == STATE_COLS) { "Row must have $STATE_COLS bytes" }
        data[row] = values[0]
        data[row + STATE_ROWS] = values[1]
        data[row + STATE_ROWS * 2] = values[2]
        data[row + STATE_ROWS * 3] = values[3]
        return this
    }

    /**
     * Sets entire column.
     * ✅ 优化：列连续存储，直接 System.arraycopy 写入。
     */
    fun setColumn(col: Int, values: ByteArray): AesState {
        require(col in 0 until STATE_COLS) { "Invalid column: $col" }
        require(values.size == STATE_ROWS) { "Column must have $STATE_ROWS bytes" }
        val base = col * STATE_ROWS
        System.arraycopy(values, 0, data, base, STATE_ROWS)
        return this
    }

    /**
     * Converts state to block bytes (column-major order).
     * ✅ 优化：扁平数组本身就是列主序，直接 copyOf 输出。
     */
    fun toBlock(): ByteArray = data.copyOf()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AesState) return false
        return data.contentEquals(other.data)
    }

    override fun hashCode(): Int = data.contentHashCode()

    override fun toString(): String = "AesState(4x4)"
}
