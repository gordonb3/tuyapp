/*
 *  Client interface for local Tuya device access
 *
 *  AES-128 ECB encrypt/decrypt module
 *
 *
 *  Copyright 2022-2026 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */


namespace Tuya {


#ifdef MBEDTLS

#include "mbedtls/aes.h"

static bool aes_128_gcm_encrypt(const unsigned char *cEncryptionKey, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize)
{
	std::string szPaddedPayload = szPayload;
	uint8_t padding = 16 - (payloadSize % 16);
	int paddedInputSize = inputSize + padding;
	
	unsigned char cPaddedInput[paddedInputSize];
	memcpy(cPaddedInput, cInputBuffer, inputSize);
	memset(cPaddedInput + inputSize, padding, padding);

	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_enc(&aes, cEncryptionKey, 128 );
	for (int i = 0; i < paddedInputSize / 16; ++i)
	{
		mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, cInputBuffer + i * 16, &cOutputBuffer[i * 16]);
		outputSize += 16;
	}
	mbedtls_aes_free(&aes);

	return true;
}


static bool aes_128_gcm_decrypt(const unsigned char *cEncryptionKey, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize)
{
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_dec(&aes, cEncryptionKey, 128);
	for (int i = 0; i < inputSize / 16; ++i)
	{
		mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, cInputBuffer + i * 16, cOutputBuffer + i * 16);
		outputSize += 16;
	}
	mbedtls_aes_free(&aes);

	//  trim padding chars from decrypted payload
	uint8_t padding = cOutputBuffer[inputSize - 1];
	if (padding <= 16)
	{
		cOutputBuffer[inputSize - padding] = 0;
		outputSize -= padding;
	}

	return true;
}

#else

#include <openssl/evp.h>

static bool aes_128_gcm_encrypt(const unsigned char *key, const unsigned char *iv, int iv_len,
                                 const unsigned char *aad, int aad_len,
                                 const unsigned char *input, int input_len,
                                 unsigned char *output, int *output_len,
                                 unsigned char *tag, int tag_len)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return false;

	int len;
	*output_len = 0;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (aad && aad_len > 0) {
		if (EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			return false;
		}
	}

	if (EVP_EncryptUpdate(ctx, output, &len, input, input_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	*output_len = len;

	if (EVP_EncryptFinal_ex(ctx, output + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	*output_len += len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

static bool aes_128_gcm_decrypt(const unsigned char *key, const unsigned char *iv, int iv_len,
                                 const unsigned char *aad, int aad_len,
                                 const unsigned char *input, int input_len,
                                 const unsigned char *tag, int tag_len,
                                 unsigned char *output, int *output_len)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return false;

	int len;
	*output_len = 0;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (aad && aad_len > 0) {
		if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			return false;
		}
	}

	if (EVP_DecryptUpdate(ctx, output, &len, input, input_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	*output_len = len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (EVP_DecryptFinal_ex(ctx, output + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	*output_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

#endif

}; // namespace Tuya


