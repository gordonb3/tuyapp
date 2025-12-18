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


namespace Tuya {

#include <openssl/hmac.h>

static void hmac_sha256(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *output)
{
	unsigned int len;
	HMAC(EVP_sha256(), key, key_len, data, data_len, output, &len);
}

}; // namespace Tuya


