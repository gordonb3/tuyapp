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

	int BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload, const std::string &szEncryptionKey) override;
	std::string DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &szEncryptionKey) override;

	bool NegotiateSessionStart(const std::string &szEncryptionKey) override;
	bool NegotiateSessionFinalize(unsigned char *buffer, const int size, const std::string &szEncryptionKey) override;

	bool ConnectToDevice(const std::string &hostname) override;

	// deprecated blocking mode only function - calls NegotiateSessionStart() and NegotiateSessionFinalize() in succession
	bool NegotiateSession(const std::string &local_key);

private:
	unsigned char m_session_key[16];
	unsigned char m_local_nonce[16];
	unsigned char m_remote_nonce[16];
	uint32_t m_seqno;

};
#endif // _tuyaAPI34

