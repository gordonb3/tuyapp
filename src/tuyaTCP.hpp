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

	bool ConnectToDevice(const std::string &hostname, const int portnumber, const uint8_t retries = 5);
	int send(unsigned char* buffer, const unsigned int size);
	int receive(unsigned char* buffer, const unsigned int maxsize, const unsigned int minsize = 28);
	void disconnect();


private:
	int m_sockfd;
	bool ResolveHost(const std::string &hostname, struct sockaddr_in& serv_addr);

#ifdef DEBUG
#include <iostream>
void exit_error(const char *msg);
#endif

};

#endif

