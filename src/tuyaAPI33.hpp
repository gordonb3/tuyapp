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

// Tuya API 3.3 Class

#ifndef _tuyaAPI33
#define _tuyaAPI33

#include "tuyaAPI.hpp"

#include <string>
#include <cstdint>

class tuyaAPI33 : public tuyaAPI
{

public:
/************************************************************************
 *									*
 *	Class construct							*
 *									*
 ************************************************************************/
	tuyaAPI33();
	~tuyaAPI33();

	int BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &payload, const std::string &encryption_key) override;
	std::string DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &encryption_key) override;

	bool ConnectToDevice(const std::string &hostname, const int portnumber, const uint8_t retries = 5) override;
	int send(unsigned char* buffer, const unsigned int size) override;
	int receive(unsigned char* buffer, const unsigned int maxsize, const unsigned int minsize = 28) override;
	void disconnect() override;


private:
	int m_sockfd;
	bool ResolveHost(const std::string &hostname, struct sockaddr_in& serv_addr);

};

#endif

