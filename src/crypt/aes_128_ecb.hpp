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


#include <openssl/evp.h>

static bool aes_128_ecb_encrypt(const unsigned char *cEncryptionKey, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize)
{
	int len;
	*outputSize = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return false;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, cEncryptionKey, nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (EVP_EncryptUpdate(ctx, cOutputBuffer, &len, cInputBuffer, inputSize) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	*outputSize = len;

	if (EVP_EncryptFinal_ex(ctx, cOutputBuffer + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	*outputSize += len;

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

static bool aes_128_ecb_decrypt(const unsigned char *cEncryptionKey, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer, int *outputSize)
{
	int len;
	*outputSize = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return false;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, cEncryptionKey, nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	EVP_CIPHER_CTX_set_padding(ctx, 1);  // Enable padding (default)

	if (EVP_DecryptUpdate(ctx, cOutputBuffer, &len, cInputBuffer, inputSize) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	*outputSize = len;

	// Don't fail if DecryptFinal fails - just use what we got from Update
	EVP_DecryptFinal_ex(ctx, cOutputBuffer + len, &len);
	*outputSize += len;

	EVP_CIPHER_CTX_free(ctx);
	return true;
}


}; // namespace Tuya


