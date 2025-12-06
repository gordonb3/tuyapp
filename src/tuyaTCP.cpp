/*
 *	Client interface for local Tuya device access
 *
 *	This is the base TCP communication class for single device threads.
 *
 *	Both async and blocking mode (default) communication is supported,
 *	allowing straight forward single task applications to be created, as
 *	well as more advanced multi threaded monitoring applications.
 *
 *	Common functions:
 *	 - ConnectToDevice(hostname|IP_address)
 *		Opens a TCP connection with the device
 *		Returns true|false indicating success or failure
 *	 - send(buffer[], size)
 *		Sends `size` bytes of `buffer` to the device
 *		Returns `size` on success or -1 if an error occurred
 *	 - receive(buffer[], maxsize, minsize)
 *		Fills `buffer` with the device's response. The additional `minsize`
 *		parameter (used in blocking mode only) defaults to 28 to skip
 *		processing of empty responses that are returned on state changing
 *		commands.
 *		Returns number of bytes received or -1 if an error occurred
 *	 - disconnect()
 *		Closes the connection with the device
 *		Returns nothing
 *	 - getlasterror()
 *		Use this instead of referencing `errno`, which may be polluted
 *		Returns the last error state of the connection
 *
 *	Async functions:
 *	 - setAsyncMode(true|false)
 *		Enables (default) or disables async operation
 *		Returns nothing
 *	 - isConnected()
 *		Returns true|false indicating if connection was successful
 *	 - isSocketWritable()
 *		Returns true|false indicating if the connection is ready for writing
 *	 - isSocketReadable()
 *		Returns true|false indicating if the connection has data to be read
 *	 - getSocketState()
 *		Returns one of Tuya::TCP::Socket::value
 *	 - setSessionReady()
 *		Dummy function needed to be able to distinguish between being connected
 *		and session negotiation (API 3.4+) having been completed. Calling this
 *		method will set the SocketState to Tuya::TCP::Socket::READY from where
 *		it will alternate with Tuya::TCP::Socket::RECEIVING
 *		Does nothing if on call SocketState is not Tuya::TCP::Socket::CONNECTED
 *		Returns true|false 
 *
 *
 *	For either method, the connection requires periodic sending of a keep-alive
 *	signal. Upto a 15 second interval appears to be generally accepted. Client apps
 *	should call getSocketState() to decide what type of message the device will
 *	accept in this case:
 *	 - Tuya::TCP::Socket::READY
 *		=> data was received - you may ask for additional DPS updates
 *	 - Tuya::TCP::Socket::RECEIVING
 *		=> no data was received yet - you may only send a `HEARTBEAT` message
 *	Sending state changing commands can be done at any point in time
 *
 *
 *
 *	Copyright 2022-2026 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *	Licensed under GNU General Public License 3.0 or later.
 *	Some rights reserved. See COPYING, AUTHORS.
 *
 *	@license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#define SOCKET_CONNECT_TIMEOUT_SECS 5
#define SOCKET_RECEIVE_TIMEOUT_SECS 2

#include "tuyaTCP.hpp"
#include <unistd.h>
#include <cstring>
#include <netdb.h>

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
#endif


tuyaTCP::tuyaTCP()
{
	m_sockfd = -1;
	m_socketState = Tuya::TCP::Socket::DISCONNECTED;
	m_asyncMode = false;
}


tuyaTCP::~tuyaTCP()
{
	disconnect();
}


void tuyaTCP::setAsyncMode(bool async)
{
	m_asyncMode = async;
}


Tuya::TCP::Socket::value tuyaTCP::getSocketState()
{
	return m_socketState;
}

bool tuyaTCP::isSocketWritable()
{
	return (getSocketEvents(POLLOUT, 0) == 0);
}


bool tuyaTCP::isSocketReadable()
{
	return (getSocketEvents(POLLIN, 0) == 0);
}


bool tuyaTCP::setSessionReady()
{
	if (m_socketState == Tuya::TCP::Socket::CONNECTED)
	{
		m_socketState = Tuya::TCP::Socket::READY;
		return true;
	}
	return false;
}


bool tuyaTCP::isConnected()
{
	switch (m_socketState)
	{
		case Tuya::TCP::Socket::NO_SUCH_HOST:
		case Tuya::TCP::Socket::NO_SOCK_AVAIL:
		case Tuya::TCP::Socket::FAILED:
		case Tuya::TCP::Socket::DISCONNECTED:
			return false;
		case Tuya::TCP::Socket::CONNECTED:
		case Tuya::TCP::Socket::READY:
		case Tuya::TCP::Socket::RECEIVING:
			return true;
		default:
			break;
	}
	// Tuya::TCP::Socket::CONNECTING
	if (isSocketWritable())
	{
		m_socketState = Tuya::TCP::Socket::CONNECTED;
		return true;
	}
	return false;
}


bool tuyaTCP::ConnectToDevice(const std::string &hostname, uint8_t retries)
{
	struct sockaddr_in serv_addr;
	bzero((char*)&serv_addr, sizeof(serv_addr));

	if ((hostname.find(':') != std::string::npos) || ((hostname[0] ^ 0x30) < 10))
	{
		if (hostname.find(':') != std::string::npos)
			serv_addr.sin_family = AF_INET6;
		else
			serv_addr.sin_family = AF_INET;
		if (inet_pton(serv_addr.sin_family, hostname.c_str(), &serv_addr.sin_addr) != 1)
		{
			m_socketState = Tuya::TCP::Socket::NO_SUCH_HOST;
			return false;
		}
	}
	else
	{
		struct addrinfo *addr;
		if (getaddrinfo(hostname.c_str(), "0", nullptr, &addr) != 0)
		{
			m_socketState = Tuya::TCP::Socket::NO_SUCH_HOST;
			return false;
		}
		struct sockaddr_in *saddr = (((struct sockaddr_in *)addr->ai_addr));
		serv_addr.sin_family = saddr->sin_family;
		memcpy(&serv_addr, saddr, sizeof(sockaddr_in));
	}

#ifdef WIN32
	m_sockfd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0 , 0 , 0);
#else
	m_sockfd = socket(AF_INET, SOCK_STREAM, 0);
#endif
	if (m_sockfd < 0)
	{
		m_socketState = Tuya::TCP::Socket::NO_SOCK_AVAIL;
		return false;
	}

	// set nonblocking mode
#ifdef WIN32
	int set = 1;
	setsockopt(m_sockfd, IPPROTO_TCP, TCP_NODELAY,  (char*) &set, sizeof(set) );
	unsigned long nonblock = 1;
	ioctlsocket(m_sockfd, FIONBIO, &nonblock);
#else
	int sockopts = fcntl(m_sockfd, F_GETFL, 0);
	if (sockopts == -1)
	{
		m_socketState = Tuya::TCP::Socket::FAILED;
		return false;
	}
	fcntl(m_sockfd, F_SETFL, sockopts | O_NONBLOCK);
#endif

	serv_addr.sin_port = htons(TUYA_COMMAND_PORT);
	if (connect(m_sockfd, (const sockaddr*)&serv_addr, sizeof(serv_addr)) == 0)
	{
		m_socketState = Tuya::TCP::Socket::CONNECTED;
		return true;
	}

#ifdef WIN32
	m_lasterror = WSAGetLastError();
	if (WSAGetLastError() == WSAEWOULDBLOCK)
#else
	m_lasterror = errno;
	if (errno == EINPROGRESS)
#endif
	{
		m_socketState = Tuya::TCP::Socket::CONNECTING;
		if (m_asyncMode)
			return true;

		if (getSocketEvents(POLLOUT, SOCKET_CONNECT_TIMEOUT_SECS) == 0)
		{
			m_socketState = Tuya::TCP::Socket::CONNECTED;
			m_lasterror = 0;
			return true;
		}
	}

#ifdef DEBUG
	std::cout << "{\"msg\":\"" << strerror(errno) << "\",\"code\":" << errno << "}\n";
#endif
	m_socketState = Tuya::TCP::Socket::FAILED;
	return false;
}


int tuyaTCP::send(unsigned char* buffer, const int size)
{
	// set socket state to indicate that caller needs to start reading
	if (m_socketState == Tuya::TCP::Socket::READY)
		m_socketState = Tuya::TCP::Socket::RECEIVING;

	int numbytes;
#ifdef WIN32
	numbytes = ::send(m_sockfd, (char*)buffer, size, 0);
	if (numbytes < 0)
		m_lasterror = WSAGetLastError();
#else
	numbytes = write(m_sockfd, buffer, size);
	if (numbytes < 0)
		m_lasterror = errno;
#endif

	return numbytes;
}


// After sending a device state change command, tuya devices send an empty `ack` reply first
// if Async mode is disabled, then setting minsize to a larger value than the empty reply
// will cause this function to ignore it and wait for the actual reply.
// If you do not specify minsize, it will default to 30 bytes (version 3.3 message protocol)
int tuyaTCP::receive(unsigned char* buffer, const int maxsize, const int minsize)
{
	int numbytes = -1;
#ifdef WIN32
	m_lasterror = WSAEWOULDBLOCK;
#else
	m_lasterror = EAGAIN;
#endif
	if (m_socketState == Tuya::TCP::Socket::READY)
	{
		// you should not be trying to read in this socket state
		return numbytes;
	}
	int timeout;
	if (m_asyncMode)
		timeout = 0;
	else
		timeout = SOCKET_RECEIVE_TIMEOUT_SECS * 1000;
	bool getnext = true;
	while ((numbytes <= minsize) && (getnext))
	{
		if (getSocketEvents(POLLIN, timeout) == 0)
		{
#ifdef WIN32
			numbytes = recv(m_sockfd, (char*)buffer, maxsize, 0 );
			if (numbytes < 0)
				m_lasterror = WSAGetLastError();
#else
			numbytes = read(m_sockfd, buffer, maxsize);
			if (numbytes < 0)
				m_lasterror = errno;
#endif
		}

		if (numbytes >= minsize)
		{
			// reset socket state to indicate that caller needs to send a new request for data
			if (m_socketState == Tuya::TCP::Socket::RECEIVING)
				m_socketState = Tuya::TCP::Socket::READY;
			return numbytes;
		}

		if (m_asyncMode)
			return -1;

		if (numbytes > 0)
		{
			// received an empty 'ack' message, continue reading
#ifdef DEBUG
			std::cout << "{\"ack\":true}\n";
#endif
			continue;
		}

		getnext = false;
	}

	return numbytes;
}


int tuyaTCP::getlasterror()
{
	return m_lasterror;
}


void tuyaTCP::disconnect()
{
	if (m_sockfd >= 0)
		close(m_sockfd);
	m_sockfd = -1;
}


/* private */ int tuyaTCP::getSocketEvents(short events, int timeout)
{
#ifdef WIN32
	struct timeval tv
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	fd_set fdw, fdr, fde;
	FD_ZERO(&fdw);
	FD_ZERO(&fdr);
	FD_ZERO(&fde);
	FD_SET(m_sockfd, &fdw);
	FD_SET(m_sockfd, &fdr);
	FD_SET(m_sockfd, &fde);
	if (select(static_cast<int>(m_sockfd + 1), &fdr, &fdw, &fde, &tv) >= 0)
	{
		// get socket options
		socklen_t len = sizeof m_lasterror;
		if (getsockopt(m_sockfd, SOL_SOCKET, SO_ERROR, (char *)&m_lasterror, &len) >= 0)
			return m_lasterror;
	}
#else
	struct pollfd fds;
	fds.fd = m_sockfd;
	fds.events = events;
	fds.revents = 0;
	int result = poll(&fds, 1, timeout * 1000);
	if (result >= 0)
	{
		if (fds.revents & (POLLERR | POLLHUP))
		{
			if (fds.revents & POLLHUP)
				m_socketState = Tuya::TCP::Socket::FAILED;
			// try to get socket error
			int sockerr;
			socklen_t len = sizeof sockerr;
			if (getsockopt(m_sockfd, SOL_SOCKET, SO_ERROR, (char *)&sockerr, &len) >= 0)
			{
				if (sockerr > 0)
					m_lasterror = sockerr;
			}
			return m_lasterror;
		}
		else if (fds.revents & events)
		{
			m_lasterror = 0;
			return m_lasterror;
		}
	}
#endif
	else
	{
		m_socketState = Tuya::TCP::Socket::FAILED;
	}
	return -1;
}

