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
static bool aes_128_gcm_encrypt(const unsigned char *cEncryptionKey, const unsigned char *iv, int iv_len, const unsigned char *aad, int aad_len, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize, unsigned char *tag, int tag_len)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return false;

	int len;
	*outputSize = 0;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, cEncryptionKey, iv) == 1)
	{
		if (!aad || (aad_len == 0) || (EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len) == 1))
		{
			if (EVP_EncryptUpdate(ctx, cOutputBuffer, &len, cInputBuffer, inputSize) == 1)
			{
				*outputSize = len;
				if (EVP_EncryptFinal_ex(ctx, cOutputBuffer + len, &len) == 1)
				{
					*outputSize += len;
					if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag) == 1)
					{
						EVP_CIPHER_CTX_free(ctx);
						return true;
					}
				}
			}
		}
	}

	EVP_CIPHER_CTX_free(ctx);
	return false;
}

static bool aes_128_gcm_decrypt(const unsigned char *cEncryptionKey, const unsigned char *iv, int iv_len, const unsigned char *aad, int aad_len, const unsigned char *cInputBuffer, int inputSize, const unsigned char *tag, int tag_len, unsigned char *cOutputBuffer, int *outputSize)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return false;

	int len;
	*outputSize = 0;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, cEncryptionKey, iv) == 1)
	{
		if (!aad || (aad_len == 0) || (EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len) == 1))
		{
			if (EVP_DecryptUpdate(ctx, cOutputBuffer, &len, cInputBuffer, inputSize) == 1)
			{
				*outputSize = len;
				if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag) == 1)
				{
					if (EVP_DecryptFinal_ex(ctx, cOutputBuffer + len, &len) == 1)
					*outputSize += len;
					EVP_CIPHER_CTX_free(ctx);
					return true;
				}
			}
		}
	}

	EVP_CIPHER_CTX_free(ctx);
	return false;
}


#endif // USE_OPENSSL

#ifdef USE_MBEDTLS

#include "mbedtls/gcm.h"

static bool aes_128_gcm_encrypt(const unsigned char *cEncryptionKey, const unsigned char *iv, int iv_len, const unsigned char *aad, int aad_len, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize, unsigned char *tag, int tag_len)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);

	if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, cEncryptionKey, 128) == 0)
	{
		if (mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, inputSize, iv, iv_len, aad, aad_len, cInputBuffer, cOutputBuffer, tag_len, tag) == 0)
		{
			*outputSize = inputSize;
			mbedtls_gcm_free(&ctx);
			return true;
		}		
	}

	mbedtls_gcm_free(&ctx);
	return false;
}


static bool aes_128_gcm_decrypt(const unsigned char *cEncryptionKey, const unsigned char *iv, int iv_len, const unsigned char *aad, int aad_len, const unsigned char *cInputBuffer, int inputSize, const unsigned char *tag, int tag_len, unsigned char *cOutputBuffer, int *outputSize)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);

	if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, cEncryptionKey, 128) == 0)
	{
		if (mbedtls_gcm_auth_decrypt(&ctx, inputSize, iv, iv_len, aad, aad_len, tag, tag_len, cInputBuffer, cOutputBuffer) == 0)
		{
			*outputSize = inputSize;
			mbedtls_gcm_free(&ctx);
			return true;
		}
	}

	mbedtls_gcm_free(&ctx);
	return false;
}

#endif // USE_MBEDTLS


}; // namespace Tuya


