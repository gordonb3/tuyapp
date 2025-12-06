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

#include "tuyaAPI.hpp"
#include "tuyaAPI31.hpp"
#include "tuyaAPI33.hpp"
#include "tuyaAPI34.hpp"

#ifdef DEBUG
#include <iostream>
#endif

tuyaAPI* tuyaAPI::create(const std::string &version)
{
	if (version == "3.1")
		return new tuyaAPI31();
	if (version == "3.3")
		return new tuyaAPI33();
	if (version == "3.4")
		return new tuyaAPI34();
	return nullptr;
}

bool tuyaAPI::NegotiateSession(const std::string &local_key)
{
	SetEncryptionKey(local_key);
	m_session_established = false;

	unsigned char send_buffer[1024];
	unsigned char recv_buffer[1024];

	while (!m_session_established)
	{
		int packet_size = BuildSessionMessage(send_buffer);
		if (packet_size < 0)
			return false;
		if (packet_size == 0)
			break;

#ifdef DEBUG
		std::cout << "dbg: session message (size=" << packet_size << "): ";
		for(int i=0; i<packet_size; ++i)
			printf("%.2x", (uint8_t)send_buffer[i]);
		std::cout << "\n";
#endif

		if (send(send_buffer, packet_size) < 0)
			return false;

		if (m_session_established)
			break;

		int recv_size = receive(recv_buffer, sizeof(recv_buffer), 0);
		if (recv_size < 0)
			return false;

#ifdef DEBUG
		std::cout << "dbg: received session message (size=" << recv_size << "): ";
		for(int i=0; i<recv_size; ++i)
			printf("%.2x", (uint8_t)recv_buffer[i]);
		std::cout << "\n";
#endif


		DecodeSessionMessage(recv_buffer, recv_size);
	}

	return true;
}
