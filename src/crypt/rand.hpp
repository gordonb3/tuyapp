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

#ifndef USE_MBEDTLS

// select default encryption routines
#define USE_OPENSSL

#endif



#ifdef USE_OPENSSL

#include <openssl/rand.h>

namespace Tuya {
static void random_bytes(unsigned char *buffer, int len)
{
	RAND_bytes(buffer, len);
}
}; // namespace Tuya

#endif // USE_OPENSSL


#ifdef USE_MBEDTLS

#include <fstream> // must be included in global namespace

namespace Tuya {
static void random_bytes(unsigned char *buffer, int len)
{
	std::fstream fr;
	fr.open("/dev/urandom", std::ios::in | std::ios::binary);
	fr.read((char*)buffer, len);
	fr.close();
}
}; // namespace Tuya

#endif // USE_MBEDTLS



