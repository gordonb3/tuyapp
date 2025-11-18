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

#define SOCKET_TIMEOUT_SECS 1

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
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#endif

#ifdef DEBUG
#include <iostream>
void exit_error(const char *msg)
{
	perror(msg);
	exit(0);
}
#endif


tuyaTCP::tuyaTCP()
{
	m_sockfd = -1;
}


tuyaTCP::~tuyaTCP()
{
	disconnect();
}


bool tuyaTCP::ConnectToDevice(const std::string &hostname, uint8_t retries)
{
	struct sockaddr_in serv_addr;
	bzero((char*)&serv_addr, sizeof(serv_addr));
	if (!ResolveHost(hostname, serv_addr))
#ifdef DEBUG
		exit_error("ERROR, no such host");
#else
		return false;
#endif

#ifdef WIN32
	m_sockfd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0 , 0 , 0);
#else
	m_sockfd = socket(AF_INET, SOCK_STREAM, 0);
#endif
	if (m_sockfd < 0)
#ifdef DEBUG
		exit_error("ERROR opening socket");
#else
		return false;
#endif

#ifdef WIN32
	int set = 1;
	setsockopt(m_sockfd, IPPROTO_TCP, TCP_NODELAY,  (char*) &set, sizeof(set) );

	fd_set fdw, fdr, fde;
	FD_ZERO(&fdw);
	FD_ZERO(&fdr);
	FD_ZERO(&fde);
	FD_SET(m_sockfd, &fdw);
	FD_SET(m_sockfd, &fdr);
	FD_SET(m_sockfd, &fde);

	unsigned long nonblock = 1;
	ioctlsocket(m_sockfd, FIONBIO, &nonblock);
#else
	struct pollfd fds;
	fds.fd = m_sockfd;
	fds.events = POLLERR | POLLOUT;
	fds.revents = 0;

	fcntl(m_sockfd, F_SETFL, O_NONBLOCK);
#endif

	int so_error;
	socklen_t len = sizeof so_error;
	serv_addr.sin_port = htons(TUYA_COMMAND_PORT);
	for (uint8_t i = 0; i < retries; i++)
	{
#ifdef WIN32
		if (connect(m_sockfd, (const sockaddr*)&serv_addr, sizeof(serv_addr)) == 0)
			return true;

		if (WSAGetLastError() == WSAEWOULDBLOCK)
		{
			if (select(static_cast<int>(m_sockfd + 1), &fdw, &fdr, &fde, &tv) > 0)
			{
				// try to get socket options
				if (getsockopt(m_sockfd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len) >= 0)
				{
					if (so_error == 0)
						return true;
				}
			}
		}
#else
		if (connect(m_sockfd, (const sockaddr*)&serv_addr, sizeof(serv_addr)) == 0)
			return true;

		if (errno == EINPROGRESS)
		{
			if (poll(&fds, 1, SOCKET_TIMEOUT_SECS * 1000) > 0)
			{
				// try to get socket options
				if (getsockopt(m_sockfd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len) >= 0)
				{
					if (so_error == 0)
						return true;
				}
			}
		}
#endif

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


int tuyaTCP::send(unsigned char* buffer, const int size)
{
#ifdef WIN32
	return ::send(m_sockfd, (char*)buffer, size, 0);
#else
	return write(m_sockfd, buffer, size);
#endif
}


// After sending a device state change command, tuya devices send an empty `ack` reply first
// if waitforanswer is enabled, then setting minsize to a larger value than the empty reply
// will cause this function to skip it and wait for the actual reply.
// If you do not specify minsize, it will default to 28 bytes (version 3.3 message protocol)
int tuyaTCP::receive(unsigned char* buffer, const int maxsize, const int minsize, bool waitforanswer)
{
	int numbytes = 0;
	int i = 0;
	while ((numbytes <= minsize) && (i < SOCKET_TIMEOUT_SECS * 500))
	{
#ifdef WIN32
		numbytes = recv(m_sockfd, (char*)buffer, maxsize, 0 );
#else
		numbytes = read(m_sockfd, buffer, maxsize);
#endif
		if (!waitforanswer)
			return numbytes;

		if (numbytes < 0) {
#ifdef WIN32
			if (WSAGetLastError() != WSAEWOULDBLOCK)
				return numbytes;
#else
			if (errno != EAGAIN)
				return numbytes;
#endif
		}
#ifdef DEBUG
		else
		{
			std::cout << "{\"ack\":true}\n";
		}
#endif
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		i++;
	}
	return numbytes;
}


void tuyaTCP::disconnect()
{
	if (m_sockfd >= 0)
		close(m_sockfd);
	m_sockfd = -1;
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
		serv_addr.sin_family = saddr->sin_family;
		memcpy(&serv_addr, saddr, sizeof(sockaddr_in));
		return true;
	}

	return false;
}

