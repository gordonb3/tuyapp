/*
 *  Client interface for local Tuya device access
 *
 *  Message authentication code module
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

#include <openssl/hmac.h>

static void hmac_sha256(const unsigned char *cEncryptionKey, int keySize, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer)
{
	unsigned int len;
	HMAC(EVP_sha256(), cEncryptionKey, keySize, cInputBuffer, inputSize, cOutputBuffer, &len);
}


#endif // USE_OPENSSL



#ifdef USE_MBEDTLS

#include <mbedtls/md.h>

static void hmac_sha256(const unsigned char *cEncryptionKey, int keySize, const unsigned char *cInputBuffer, int inputSize, unsigned char *cOutputBuffer)
{
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md_hmac(md_info, cEncryptionKey, keySize, cInputBuffer, inputSize, cOutputBuffer);

}

#endif // USE_MBEDTLS

}; // namespace Tuya


