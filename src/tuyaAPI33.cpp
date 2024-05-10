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

#define DEBUG

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


#define PROTOCOL_33_HEADER_SIZE 16
#define PROTOCOL_33_EXTRA_HEADER_SIZE 15
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 8



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


int tuyaAPI33::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload, const std::string &encryption_key)
{
	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_33_HEADER_SIZE);
	// set message prefix
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	// set command code at int32 @msg[8] (single byte value @msg[11])
	buffer[11] = command;
	bufferpos += (int)PROTOCOL_33_HEADER_SIZE;

	if ((command != TUYA_DP_QUERY) && (command != TUYA_UPDATEDPS))
	{
		// add the protocol 3.3 secondary header
		unsigned char* extraHeader = &buffer[bufferpos];
		memset(extraHeader, 0, PROTOCOL_33_EXTRA_HEADER_SIZE);
		strcpy((char*)extraHeader, "3.3");
		bufferpos += PROTOCOL_33_EXTRA_HEADER_SIZE;
	}

	unsigned char* cEncryptedPayload = &buffer[bufferpos];
	int payloadSize = (int)szPayload.length();
	memset(cEncryptedPayload, 0, payloadSize + 16);
	int encryptedSize = 0;
	int encryptedChars = 0;

	try
	{
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)encryption_key.c_str(), nullptr);
		EVP_EncryptUpdate(ctx, cEncryptedPayload, &encryptedChars, (unsigned char*)szPayload.c_str(), payloadSize);
		encryptedSize = encryptedChars;
		EVP_EncryptFinal_ex(ctx, cEncryptedPayload + encryptedChars, &encryptedChars);
		encryptedSize += encryptedChars;
		EVP_CIPHER_CTX_free(ctx);
	}
	catch (const std::exception& e)
	{
		// encryption failure
		return -1;
	}

#ifdef DEBUG
	std::cout << "dbg: encrypted payload (size=" << encryptedSize << "): ";
	for(int i=0; i<encryptedSize; ++i)
		printf("%.2x", (uint8_t)cEncryptedPayload[i]);
	std::cout << "\n";
#endif

	bufferpos += encryptedSize;
	unsigned char* cMessageTrailer = &buffer[bufferpos];

	// update message size in int32 @buffer[12]
	int buffersize = bufferpos + MESSAGE_TRAILER_SIZE;
	buffer[14] = ((buffersize - PROTOCOL_33_HEADER_SIZE) & 0x0000FF00) >> 8;
	buffer[15] = (buffersize - PROTOCOL_33_HEADER_SIZE) & 0x000000FF;

	// calculate CRC
	unsigned long crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, buffer, bufferpos) & 0xFFFFFFFF;

	// fill the message trailer
	cMessageTrailer[0] = (crc & 0xFF000000) >> 24;
	cMessageTrailer[1] = (crc & 0x00FF0000) >> 16;
	cMessageTrailer[2] = (crc & 0x0000FF00) >> 8;
	cMessageTrailer[3] = (crc & 0x000000FF);

	cMessageTrailer[4] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	cMessageTrailer[5] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	cMessageTrailer[6] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	cMessageTrailer[7] = (MESSAGE_SUFFIX & 0x000000FF);

#ifdef DEBUG
	std::cout << "dbg: complete message: ";
	for(int i=0; i<(int)(buffersize); ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}


std::string tuyaAPI33::DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &encryption_key)
{
	std::string result;

	int bufferpos = 0;

	while (bufferpos < size)
	{
		unsigned char* cTuyaResponse = &buffer[bufferpos];
		int messageSize = (int)((uint8_t)cTuyaResponse[15] + ((uint8_t)cTuyaResponse[14] << 8) + PROTOCOL_33_HEADER_SIZE);
		int retcode = (int)((uint8_t)cTuyaResponse[19] + ((uint8_t)cTuyaResponse[18] << 8));

		if (retcode != 0)
		{
			char cErrorMessage[50];
			sprintf(cErrorMessage, "{\"msg\":\"device returned error %d\"}", retcode);
			result.append(cErrorMessage);
			bufferpos += messageSize;
			continue;
		}


		// verify crc
		unsigned int crc_sent = ((uint8_t)cTuyaResponse[messageSize - 8] << 24) + ((uint8_t)cTuyaResponse[messageSize - 7] << 16) + ((uint8_t)cTuyaResponse[messageSize - 6] << 8) + (uint8_t)cTuyaResponse[messageSize - 5];
		unsigned int crc = crc32(0L, Z_NULL, 0) & 0xFFFFFFFF;
		crc = crc32(crc, cTuyaResponse, messageSize - 8) & 0xFFFFFFFF;

		if (crc == crc_sent)
		{
			unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_33_HEADER_SIZE + sizeof(retcode)];
			int payloadSize = (int)(messageSize - PROTOCOL_33_HEADER_SIZE - sizeof(retcode) - MESSAGE_TRAILER_SIZE);
			// test for presence of secondary protocol 3.3 header (odd message size)
			if ((cTuyaResponse[15] & 0x1) && (cEncryptedPayload[0] == '3') && (cEncryptedPayload[1] == '.') && (cEncryptedPayload[2] == '3'))
			{
				cEncryptedPayload += 15;
				payloadSize -= 15;
			}

			unsigned char* cDecryptedPayload = new unsigned char[payloadSize + 16];
			memset(cDecryptedPayload, 0, payloadSize + 16);
			int decryptedSize = 0;
			int decryptedChars = 0;

			try
			{
				EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
				EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)encryption_key.c_str(), nullptr);
				EVP_DecryptUpdate(ctx, cDecryptedPayload, &decryptedChars, cEncryptedPayload, payloadSize);
				decryptedSize = decryptedChars;
				EVP_DecryptFinal_ex(ctx, cDecryptedPayload + decryptedSize, &decryptedChars);
				decryptedSize += decryptedChars;
				EVP_CIPHER_CTX_free(ctx);
				result.append((char*)cDecryptedPayload);
			}
			catch (const std::exception& e)
			{
				result.append("{\"msg\":\"error decrypting payload\"}");
			}
		}
		else
			result.append("{\"msg\":\"crc error\"}");

		bufferpos += messageSize;
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


int tuyaAPI33::send(unsigned char* buffer, const unsigned int size)
{
#ifdef WIN32
	return ::send(m_sockfd, (char*)buffer, size, 0);
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
		numbytes = (unsigned int)recv(m_sockfd, (char*)buffer, maxsize, 0 );
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

