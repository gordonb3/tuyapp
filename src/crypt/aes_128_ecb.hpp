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


#ifndef USE_MBEDTLS

// select default encryption routines
#define USE_OPENSSL

#endif


namespace Tuya {

#ifdef USE_OPENSSL


#include <openssl/evp.h>

static bool aes_128_ecb_encrypt(const unsigned char *cEncryptionKey, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize)
{
	int len;
	*outputSize = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return false;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, cEncryptionKey, nullptr) == 1)
	{
		if (EVP_EncryptUpdate(ctx, cOutputBuffer, &len, cInputBuffer, inputSize) == 1)
		{
			*outputSize = len;
			if (EVP_EncryptFinal_ex(ctx, cOutputBuffer + len, &len) == 1)
			{
				*outputSize += len;
				EVP_CIPHER_CTX_free(ctx);
				return true;
			}
		}
	}

	EVP_CIPHER_CTX_free(ctx);
	return false;
}

static bool aes_128_ecb_decrypt(const unsigned char *cEncryptionKey, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize)
{
	int len;
	*outputSize = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return false;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, cEncryptionKey, nullptr) == 1)
	{
		EVP_CIPHER_CTX_set_padding(ctx, 1);  // Enable padding (default)
		if (EVP_DecryptUpdate(ctx, cOutputBuffer, &len, cInputBuffer, inputSize) == 1)
		{
			*outputSize = len;
			EVP_DecryptFinal_ex(ctx, cOutputBuffer + len, &len);
			*outputSize += len;
			EVP_CIPHER_CTX_free(ctx);
			return true;
		}
	}

	EVP_CIPHER_CTX_free(ctx);
	return false;
}

#endif // USE_OPENSSL


#ifdef USE_MBEDTLS

#include "mbedtls/aes.h"

static bool aes_128_ecb_encrypt(const unsigned char *cEncryptionKey, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize)
{
//	std::string szPaddedPayload = szPayload;
	uint8_t padding = 16 - (inputSize % 16);
	int paddedInputSize = inputSize + padding;
	
	unsigned char cPaddedInput[paddedInputSize];
	memcpy(cPaddedInput, cInputBuffer, inputSize);
	memset(cPaddedInput + inputSize, padding, padding);

	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_enc(&aes, cEncryptionKey, 128 );
	*outputSize = 0;
	for (int i = 0; i < (paddedInputSize >> 4); ++i)
	{
		mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, cInputBuffer + (i << 4), &cOutputBuffer[(i << 4)]);
		*outputSize += 16;
	}
	mbedtls_aes_free(&aes);

	return true;
}


static bool aes_128_ecb_decrypt(const unsigned char *cEncryptionKey, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize)
{
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_dec(&aes, cEncryptionKey, 128);
	for (int i = 0; i < (inputSize >> 4); ++i)
	{
		mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, cInputBuffer + (i << 4), cOutputBuffer + (i << 4));
		*outputSize += 16;
	}
	mbedtls_aes_free(&aes);

	//  trim padding chars from decrypted payload
	uint8_t padding = cOutputBuffer[inputSize - 1];
	if (padding <= 16)
	{
		cOutputBuffer[inputSize - padding] = 0;
		*outputSize -= padding;
	}

	return true;
}

#endif // USE_MBEDTLS

}; // namespace Tuya

