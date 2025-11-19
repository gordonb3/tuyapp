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

// Tuya API 3.4 Class

#ifndef _tuyaAPI34
#define _tuyaAPI34

#include "tuyaAPI.hpp"

#include <string>
#include <cstdint>

class tuyaAPI34 : public tuyaAPI
{

public:
/************************************************************************
 *									*
 *	Class construct							*
 *									*
 ************************************************************************/
	tuyaAPI34();

	void SetEncryptionKey(const std::string &key) override;
	bool NegotiateSession(const std::string &local_key) override;
	int BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &payload, const std::string &encryption_key = "") override;
	std::string DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &encryption_key = "") override;

private:
	unsigned char m_session_key[16];
	unsigned char m_local_nonce[16];
	unsigned char m_remote_nonce[16];
	bool m_session_established;
	uint32_t m_seqno;

	int BuildSessionMessage(unsigned char *buffer, const uint8_t command, const std::string &payload);
	std::string DecodeSessionMessage(unsigned char* buffer, const int size);

};
#endif // _tuyaAPI34

