/*
 *	Client interface for local Tuya device access
 *
 *	Copyright 2022-2024 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *	Licensed under GNU General Public License 3.0 or later.
 *	Some rights reserved. See COPYING, AUTHORS.
 *
 *	@license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#define SOCKET_TIMEOUT_SECS 5

#include "tuyaTCP.hpp"
#include <netdb.h>
#include <zlib.h>
#include <thread>
#include <chrono>
#include <cstring>

#ifdef WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <io.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef DEBUG
void tuyaTCP::exit_error(const char *msg)
{
	perror(msg);
	exit(0);
}
#endif


tuyaTCP::tuyaTCP()
{
}


tuyaTCP::~tuyaTCP()
{
	disconnect();
}


bool tuyaTCP::ConnectToDevice(const std::string &hostname, const int portnumber, uint8_t retries)
{
	struct sockaddr_in serv_addr;
	bzero((char*)&serv_addr, sizeof(serv_addr));
	if (!ResolveHost(hostname, serv_addr))
#ifdef DEBUG
		exit_error("ERROR, no such host");
#else
		return false;
#endif

	m_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (m_sockfd < 0)
#ifdef DEBUG
		exit_error("ERROR opening socket");
#else
		return false;
#endif

	serv_addr.sin_port = htons(portnumber);

#ifdef WIN32
	WSAStartup();
	int timeout = SOCKET_TIMEOUT_SECS * 1000;
#else
	struct timeval timeout;
	timeout.tv_sec = SOCKET_TIMEOUT_SECS;
	timeout.tv_usec = 0;
#endif
	setsockopt(m_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);

	for (uint8_t i = 0; i < retries; i++)
	{
		if (connect(m_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0)
			return true;
#ifdef DEBUG
		if (i < retries)
			std::cout << "{\"msg\":\"" << strerror(errno) << "\",\"code\":" << errno << "}\n";
		else
			exit_error("ERROR, connection failed");
#endif
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}
	return false;
}


int tuyaTCP::send(unsigned char* buffer, const unsigned int size)
{
#ifdef WIN32
	return ::send(m_sockfd, (char*)buffer, size, 0);
#else
	return write(m_sockfd, buffer, size);
#endif
}


int tuyaTCP::receive(unsigned char* buffer, const unsigned int maxsize, const unsigned int minsize)
{
#ifdef WIN32
	unsigned int numbytes = (unsigned int)recv(m_sockfd, buffer, maxsize, 0 );
#else
	unsigned int numbytes = (unsigned int)read(m_sockfd, buffer, maxsize);
#endif
	while (numbytes <= minsize)
	{
		// after sending a device state change command tuya devices send an empty `ack` reply first
		// wait for 100ms to allow device to commit and then retry for the answer that we want
#ifdef DEBUG
		std::cout << "{\"ack\":true}\n";
#endif
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
#ifdef WIN32
		numbytes = (unsigned int)recv(m_sockfd, (char*)buffer, maxsize, 0 );
#else
		numbytes = (unsigned int)read(m_sockfd, buffer, maxsize);
#endif
	}
	return (int)numbytes;
}


void tuyaTCP::disconnect()
{
	close(m_sockfd);
	m_sockfd = 0;
}


/* private */ bool tuyaTCP::ResolveHost(const std::string &hostname, struct sockaddr_in& serv_addr)
{
	if ((hostname[0] ^ 0x30) < 10)
	{
		serv_addr.sin_family = AF_INET;
		if (inet_pton(AF_INET, hostname.c_str(), &serv_addr.sin_addr) == 1)
			return true;
	}
	if (hostname.find(':') != std::string::npos)
	{
		serv_addr.sin_family = AF_INET6;
		if (inet_pton(AF_INET6, hostname.c_str(), &serv_addr.sin_addr) == 1)
			return true;
	}
	struct addrinfo *addr;
	if (getaddrinfo(hostname.c_str(), "0", nullptr, &addr) == 0)
	{
		struct sockaddr_in *saddr = (((struct sockaddr_in *)addr->ai_addr));
		memcpy(&serv_addr, saddr, sizeof(sockaddr_in));
		return true;
	}

	return false;
}

