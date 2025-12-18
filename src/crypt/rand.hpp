/*
 *  Client interface for local Tuya device access
 *
 *  Random bytes sequence generator
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

#include <openssl/rand.h>

static void random_bytes(unsigned char *buffer, int len)
{
	RAND_bytes(buffer, len);
}

}; // namespace Tuya

