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

namespace Tuya {

#include <openssl/evp.h>

static void md5_hash(const unsigned char *data, int data_len, unsigned char *output)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int len;

	EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
	EVP_DigestUpdate(ctx, data, data_len);
	EVP_DigestFinal_ex(ctx, output, &len);
	EVP_MD_CTX_free(ctx);
}

}; // namespace Tuya


