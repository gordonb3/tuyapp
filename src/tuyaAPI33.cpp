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

#define SOCKET_TIMEOUT_SECS 5

#include "tuyaAPI33.hpp"
#include <netdb.h>
#include <zlib.h>
#include <sstream>
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

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef DEBUG
#include <iostream>

void exit_error(const char *msg)
{
	perror(msg);
	exit(0);
}
#endif

tuyaAPI33::tuyaAPI33()
{
}

tuyaAPI33::~tuyaAPI33()
{
	disconnect();
}


int tuyaAPI33::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, std::string payload, const std::string &encryption_key)
{
	// pad payload to a multiple of 16 bytes
	int payload_len = (int)payload.length();
	uint8_t padding = 16 - (payload_len % 16);
	for (int i = 0; i < padding; i++)
		payload.insert(payload.end(), padding);
	payload_len = (int)payload.length();

#ifdef DEBUG
	std::cout << "dbg: padded payload (len=" << payload_len << "): ";
	for(int i=0; i<payload_len; ++i)
		printf("%.2x", (uint8_t)payload[i]);
	std::cout << "\n";
#endif

	unsigned char* encryptedpayload = new unsigned char[payload_len + 16];
	memset(encryptedpayload, 0, payload_len + 16);
	int encryptedsize = 0;

	try
	{
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)encryption_key.c_str(), nullptr);
		EVP_EncryptUpdate(ctx, encryptedpayload, &encryptedsize, (unsigned char*)payload.c_str(), payload_len);
		EVP_CIPHER_CTX_free(ctx);
	}
	catch (const std::exception& e)
	{
		return -1;
	}

#ifdef DEBUG
	std::cout << "dbg: encrypted payload: ";
	for(int i=0; i<encryptedsize; ++i)
		printf("%.2x", (uint8_t)encryptedpayload[i]);
	std::cout << "\n";
#endif

	bcopy(MESSAGE_SEND_HEADER, (char*)&buffer[0], sizeof(MESSAGE_SEND_HEADER));

	int payload_pos = (int)sizeof(MESSAGE_SEND_HEADER);
	if ((command != TUYA_DP_QUERY) && (command != TUYA_UPDATEDPS))
	{
		// add the protocol 3.3 secondary header
		bcopy(PROTOCOL_33_HEADER, (char*)&buffer[payload_pos], sizeof(PROTOCOL_33_HEADER));
		payload_pos += sizeof(PROTOCOL_33_HEADER);
	}
	bcopy(encryptedpayload, (char*)&buffer[payload_pos], payload_len);
	bcopy(MESSAGE_SEND_TRAILER, (char*)&buffer[payload_pos + payload_len], sizeof(MESSAGE_SEND_TRAILER));

	// insert command code in int32 @msg[8] (single byte value @msg[11])
	buffer[11] = command;
	// insert message size in int32 @msg[12]
	buffer[14] = ((payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER) - sizeof(MESSAGE_SEND_HEADER)) & 0xFF00) >> 8;
	buffer[15] = (payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER) - sizeof(MESSAGE_SEND_HEADER)) & 0xFF;

	// calculate CRC
	unsigned long crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, buffer, payload_pos + payload_len) & 0xFFFFFFFF;
	buffer[payload_pos + payload_len] = (crc & 0xFF000000) >> 24;
	buffer[payload_pos + payload_len + 1] = (crc & 0x00FF0000) >> 16;
	buffer[payload_pos + payload_len + 2] = (crc & 0x0000FF00) >> 8;
	buffer[payload_pos + payload_len + 3] = crc & 0x000000FF;

#ifdef DEBUG
	std::cout << "dbg: complete message: ";
	for(int i=0; i<(int)(payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER)); ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return (int)(payload_pos + payload_len + sizeof(MESSAGE_SEND_TRAILER));
}


std::string tuyaAPI33::DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &encryption_key)
{
	std::string result;

	int message_start = 0;

#ifdef DEBUG
	std::cout << "dbg: received message: ";
	for(int i=0; i<(int)(size); ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	while (message_start < size)
	{
		unsigned char* message = &buffer[message_start];
		unsigned char *encryptedpayload = &message[sizeof(MESSAGE_SEND_HEADER) + sizeof(int)];
		int message_size = (int)((uint8_t)message[15] + ((uint8_t)message[14] << 8) + sizeof(MESSAGE_SEND_HEADER));


		// verify crc
		unsigned int crc_sent = ((uint8_t)message[message_size - 8] << 24) + ((uint8_t)message[message_size - 7] << 16) + ((uint8_t)message[message_size - 6] << 8) + (uint8_t)message[message_size - 5];
		unsigned int crc = crc32(0L, Z_NULL, 0) & 0xFFFFFFFF;
		crc = crc32(crc, message, message_size - 8) & 0xFFFFFFFF;

		if (crc == crc_sent)
		{
			int payload_len = (int)(message_size - sizeof(MESSAGE_SEND_HEADER) - sizeof(int) - sizeof(MESSAGE_SEND_TRAILER));
			// test for presence of secondary protocol 3.3 header (odd message size)
			if ((message[15] & 0x1) && (encryptedpayload[0] == '3') && (encryptedpayload[1] == '.') && (encryptedpayload[2] == '3'))
			{
				encryptedpayload += 15;
				payload_len -= 15;
			}

			unsigned char* decryptedpayload = new unsigned char[payload_len + 16];
			memset(decryptedpayload, 0, payload_len + 16);
			int decryptedsize = 0;

			try
			{
				EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
				EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)encryption_key.c_str(), nullptr);
				EVP_DecryptUpdate(ctx, decryptedpayload, &decryptedsize, encryptedpayload, payload_len);
				EVP_CIPHER_CTX_free(ctx);

				// trim padding chars from decrypted payload
				uint8_t padding = decryptedpayload[payload_len - 1];
				if (padding <= 16)
					decryptedpayload[payload_len - padding] = 0;

				result.append((char*)decryptedpayload);
			}
			catch (const std::exception& e)
			{
				result.append("{\"msg\":\"error decrypting payload\"}");
			}
		}
		else
			result.append("{\"msg\":\"crc error\"}");

		message_start += message_size;
	}
	return result;
}


/* private */ bool tuyaAPI33::ResolveHost(const std::string &hostname, struct sockaddr_in& serv_addr)
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


bool tuyaAPI33::ConnectToDevice(const std::string &hostname, const int portnumber, uint8_t retries)
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


int tuyaAPI33::send(unsigned char* buffer, const unsigned int size)
{
#ifdef WIN32
	return send(m_sockfd, buffer, size, 0);
#else
	return write(m_sockfd, buffer, size);
#endif
}


int tuyaAPI33::receive(unsigned char* buffer, const unsigned int maxsize, const unsigned int minsize)
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
		numbytes = (unsigned int)recv(m_sockfd, buffer, maxsize, 0 );
#else
		numbytes = (unsigned int)read(m_sockfd, buffer, maxsize);
#endif
	}
	return (int)numbytes;
}

void tuyaAPI33::disconnect()
{
	close(m_sockfd);
	m_sockfd = 0;
}

