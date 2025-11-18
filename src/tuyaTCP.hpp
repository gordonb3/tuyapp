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

// Tuya TCP Class

#ifndef _tuyaTCP
#define _tuyaTCP

// Tuya Local Access TCP Port
#define TUYA_COMMAND_PORT 6668

#include "tuyaTCP.hpp"

#include <string>
#include <cstdint>

class tuyaTCP
{

public:
/************************************************************************
 *									*
 *	Class construct							*
 *									*
 ************************************************************************/
	tuyaTCP();
	~tuyaTCP();

	virtual bool ConnectToDevice(const std::string &hostname, const uint8_t retries = 5);
	int send(unsigned char* buffer, const int size);
	int receive(unsigned char* buffer, const int maxsize, const int minsize = 28, bool waitforanswer = true);
	void disconnect();

private:
	int m_sockfd;
	bool ResolveHost(const std::string &hostname, struct sockaddr_in& serv_addr);

};

#endif

