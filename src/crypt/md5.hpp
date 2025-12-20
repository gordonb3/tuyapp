/*
 *  Client interface for local Tuya device access
 *
 *  MD5 hash module
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

static void md5_hash(const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int len;

	EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
	EVP_DigestUpdate(ctx, cInputBuffer, inputSize);
	EVP_DigestFinal_ex(ctx, cOutputBuffer, &len);
	EVP_MD_CTX_free(ctx);
}


#endif // USE_OPENSSL


#ifdef USE_MBEDTLS

#include <mbedtls/md.h>

static void md5_hash(const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer)
{
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
	mbedtls_md(md_info, cInputBuffer, inputSize, cOutputBuffer);
}

#endif // USE_MBEDTLS

}; // namespace Tuya


