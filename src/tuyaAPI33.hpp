/*
 *  Client interface for local Tuya device access
 *
 *  API 3.3 module
 *
 *
 *  Copyright 2022-2026 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */


#ifndef _tuyaAPI33
#define _tuyaAPI33

#include "tuyaAPI.hpp"

#include <string>
#include <cstdint>

class tuyaAPI33 : public tuyaAPI
{

public:
	tuyaAPI33();

	int BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &payload, const std::string &encryption_key) override;
	std::string DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &encryption_key) override;

private:
	uint32_t m_seqno;

};
#endif // _tuyaAPI33

