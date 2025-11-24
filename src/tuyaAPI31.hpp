/*
 *  Client interface for local Tuya device access
 *
 *  Copyright 2022-2024 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

// Tuya API 3.1 Class

#ifndef _tuyaAPI31
#define _tuyaAPI31

#include "tuyaAPI.hpp"

#include <string>
#include <cstdint>

class tuyaAPI31 : public tuyaAPI
{

public:
	tuyaAPI31() { m_protocol = Protocol::v31; }

	int BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload, const std::string &szEncryptionkey="") override;
	std::string DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &szEncryptionkey="") override;

private:
	int encode_base64( const unsigned char *input_str, int input_size, unsigned char *output_str);
	std::string make_md5_digest(const std::string &str);

};
#endif // _tuyaAPI31

