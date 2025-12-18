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

// Tuya API 3.5 Class

#ifndef _tuyaAPI35
#define _tuyaAPI35

#include "tuyaAPI.hpp"

#include <string>
#include <cstdint>

class tuyaAPI35 : public tuyaAPI
{

public:
/************************************************************************
 *									*
 *	Class construct							*
 *									*
 ************************************************************************/
	tuyaAPI35();

	int BuildTuyaMessage(unsigned char *cMessageBuffer, const uint8_t command, const std::string &payload, const std::string &szEncryptionKey) override;
	std::string DecodeTuyaMessage(unsigned char *cMessageBuffer, const int size, const std::string &encryption_key) override;

	bool NegotiateSessionStart(const std::string &szEncryptionKey) override;
	bool NegotiateSessionFinalize(unsigned char *cMessageBuffer, const int buffersize, const std::string &szEncryptionKey) override;

	// deprecated blocking mode only function - calls NegotiateSessionStart() and NegotiateSessionFinalize() in succession
	bool NegotiateSession(const std::string &local_key) override;


private:
	unsigned char m_session_key[16];
	unsigned char m_local_nonce[16];
	unsigned char m_remote_nonce[16];
	uint32_t m_seqno;

};

#endif // _tuyaAPI35
