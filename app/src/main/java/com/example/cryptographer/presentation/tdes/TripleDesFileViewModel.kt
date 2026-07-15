package com.example.cryptographer.presentation.tdes

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.cryptographer.R
import com.example.cryptographer.application.common.views.KeyView
import com.example.cryptographer.application.queries.key.readall.LoadAllKeysQuery
import com.example.cryptographer.application.queries.key.readall.LoadAllKeysQueryHandler
import com.example.cryptographer.application.queries.key.readbyid.LoadKeyQuery
import com.example.cryptographer.application.queries.key.readbyid.LoadKeyQueryHandler
import com.example.cryptographer.domain.text.entities.EncryptionKey
import com.example.cryptographer.domain.text.valueobjects.EncryptionAlgorithm
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Base64
import javax.inject.Inject

/**
 * ViewModel for Triple DES file encryption/decryption screen.
 */
@HiltViewModel
class TripleDesFileViewModel @Inject constructor(
    private val presenter: TripleDesFilePresenter,
    private val loadKeyHandler: LoadKeyQueryHandler,
    private val loadAllKeysHandler: LoadAllKeysQueryHandler,
    @param:ApplicationContext private val context: Context,
) : ViewModel() {
    private val logger = KotlinLogging.logger {}

    private val _uiState = MutableStateFlow(TripleDesFileUiState())
    val uiState: StateFlow<TripleDesFileUiState> = _uiState.asStateFlow()

    private val _availableKeys = MutableStateFlow<List<KeyView>>(emptyList())
    val availableKeys: StateFlow<List<KeyView>> = _availableKeys.asStateFlow()

    init {
        loadAvailableKeys()
    }

    fun selectKey(keyId: String) {
        logger.debug { "Selecting key: keyId=$keyId" }
        viewModelScope.launch {
            val query = LoadKeyQuery(keyId)
            loadKeyHandler(query)
                .onSuccess { keyView ->
                    if (keyView.algorithm != EncryptionAlgorithm.TDES_112 &&
                        keyView.algorithm != EncryptionAlgorithm.TDES_168
                    ) {
                        _uiState.value = _uiState.value.copy(
                            error = context.getString(R.string.error_key_not_tdes),
                        )
                        return@launch
                    }

                    val key = EncryptionKey(
                        value = Base64.getDecoder().decode(keyView.keyBase64),
                        algorithm = keyView.algorithm,
                    )
                    _uiState.value = _uiState.value.copy(
                        selectedKey = key,
                        selectedKeyId = keyId,
                        error = null,
                    )
                }
                .onFailure { error ->
                    logger.error(error) { "Failed to load key: keyId=$keyId" }
                    _uiState.value = _uiState.value.copy(
                        error = context.getString(R.string.error_failed_to_load_key, error.message ?: ""),
                    )
                }
        }
    }

    fun updateEncryptInputPath(path: String) {
        _uiState.value = _uiState.value.copy(
            encryptInputPath = path,
            error = null,
        )
    }

    fun updateEncryptOutputPath(path: String) {
        _uiState.value = _uiState.value.copy(
            encryptOutputPath = path,
            error = null,
        )
    }

    fun updateDecryptInputPath(path: String) {
        _uiState.value = _uiState.value.copy(
            decryptInputPath = path,
            error = null,
        )
    }

    fun updateDecryptOutputPath(path: String) {
        _uiState.value = _uiState.value.copy(
            decryptOutputPath = path,
            error = null,
        )
    }

    fun encryptFile() {
        val inputPath = _uiState.value.encryptInputPath
        val outputPath = _uiState.value.encryptOutputPath
        val selectedKey = _uiState.value.selectedKey

        val validationError = when {
            inputPath.isBlank() -> context.getString(R.string.error_enter_input_file_path)
            outputPath.isBlank() -> context.getString(R.string.error_enter_output_file_path)
            selectedKey == null -> context.getString(R.string.error_select_key_to_encrypt)
            else -> null
        }

        if (validationError != null) {
            _uiState.value = _uiState.value.copy(error = validationError)
        } else {
            val key = requireNotNull(selectedKey)
            viewModelScope.launch {
                _uiState.value = _uiState.value.copy(isLoading = true, error = null)
                withContext(Dispatchers.IO) {
                    presenter.encryptFile(inputPath, outputPath, key)
                }
                    .onSuccess { info ->
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            encryptResultPath = info.outputPath,
                            ivBase64 = info.ivBase64 ?: "",
                            error = null,
                        )
                    }
                    .onFailure { error ->
                        logger.error(error) { "File encryption failed: ${error.message}" }
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            error = context.getString(R.string.error_encryption_failed, error.message ?: ""),
                        )
                    }
            }
        }
    }

    fun decryptFile() {
        val inputPath = _uiState.value.decryptInputPath
        val outputPath = _uiState.value.decryptOutputPath
        val selectedKey = _uiState.value.selectedKey

        val validationError = when {
            inputPath.isBlank() -> context.getString(R.string.error_enter_encrypted_file_path)
            outputPath.isBlank() -> context.getString(R.string.error_enter_output_file_path)
            selectedKey == null -> context.getString(R.string.error_select_key_to_decrypt)
            else -> null
        }

        if (validationError != null) {
            _uiState.value = _uiState.value.copy(error = validationError)
        } else {
            val key = requireNotNull(selectedKey)
            viewModelScope.launch {
                _uiState.value = _uiState.value.copy(isLoading = true, error = null)
                withContext(Dispatchers.IO) {
                    presenter.decryptFile(inputPath, outputPath, key)
                }
                    .onSuccess { info ->
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            decryptResultPath = info.outputPath,
                            error = null,
                        )
                    }
                    .onFailure { error ->
                        logger.error(error) { "File decryption failed: ${error.message}" }
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            error = context.getString(R.string.error_decryption_failed, error.message ?: ""),
                        )
                    }
            }
        }
    }

    fun loadAvailableKeys() {
        viewModelScope.launch {
            val query = LoadAllKeysQuery
            loadAllKeysHandler(query)
                .onSuccess { keyViews ->
                    _availableKeys.value = keyViews.filter {
                        it.algorithm == EncryptionAlgorithm.TDES_112 || it.algorithm == EncryptionAlgorithm.TDES_168
                    }
                }
                .onFailure { error ->
                    logger.error(error) { "Failed to load available keys: ${error.message}" }
                }
        }
    }

    fun clearAll() {
        _uiState.value = TripleDesFileUiState(
            selectedKey = _uiState.value.selectedKey,
            selectedKeyId = _uiState.value.selectedKeyId,
        )
    }
}
