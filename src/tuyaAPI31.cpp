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

#include "tuyaAPI31.hpp"
#include <netdb.h>
#include <zlib.h>
#include <sstream>
#include <iomanip>
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


#include <sstream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>


#define PROTOCOL_31_HEADER_SIZE 16
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 8


#ifdef DEBUG
#include <iostream>

void exit_error(const char *msg)
{
	perror(msg);
	exit(0);
}
#endif

tuyaAPI31::tuyaAPI31()
{
}

tuyaAPI31::~tuyaAPI31()
{
	disconnect();
}


int tuyaAPI31::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload, const std::string &encryption_key = "")
{
	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_31_HEADER_SIZE);
	// set message prefix
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	// set command code at int32 @buffer[8] (single byte value @buffer[11])
	buffer[11] = command;
	bufferpos += (int)PROTOCOL_31_HEADER_SIZE;

	int payloadSize = (int)szPayload.length();
	if (!encryption_key.empty())
	{
		unsigned char* cEncryptedPayload = &buffer[bufferpos];
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


		unsigned char cBase64Payload[200];
		payloadSize = encode_base64( (unsigned char *)cEncryptedPayload, encryptedSize, &cBase64Payload[0]);

		// add 3.1 info
		std::string premd5 = "data=";
		premd5.append((char *)cBase64Payload);
		premd5.append("||lpv=3.1||");
		premd5.append(encryption_key);
		std::string md5str = make_md5_digest(premd5);
		std::string md5mid = (char *)&md5str[8];
		std::string header = "3.1";
		header.append(md5mid);
		bcopy(header.c_str(), &buffer[bufferpos], header.length());
		bufferpos += header.length();
		cEncryptedPayload = &buffer[bufferpos];
		strcpy((char *)cEncryptedPayload,(char *)cBase64Payload);
		bufferpos += payloadSize;

#ifdef DEBUG
		std::cout << "dbg: encrypted payload (size=" << payloadSize << "): ";
		for(int i=0; i<payloadSize; ++i)
			printf("%.2x", (uint8_t)cEncryptedPayload[i]);
		std::cout << "\n";
#endif
	}
	else
	{
		unsigned char* cPayload = &buffer[bufferpos];
		memcpy((void *)cPayload, (void *)szPayload.c_str(), payloadSize + 1);
		bufferpos += payloadSize;
	}

	unsigned char* cMessageTrailer = &buffer[bufferpos];

	// update message size in int32 @buffer[12]
	int buffersize = bufferpos + MESSAGE_TRAILER_SIZE;
	buffer[14] = ((buffersize - PROTOCOL_31_HEADER_SIZE) & 0x0000FF00) >> 8;
	buffer[15] = (buffersize - PROTOCOL_31_HEADER_SIZE) & 0x000000FF;

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


std::string tuyaAPI31::DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &encryption_key)
{
	std::string result;

	int bufferpos = 0;

	while (bufferpos < size)
	{
		unsigned char* cTuyaResponse = &buffer[bufferpos];
		int messageSize = (int)((uint8_t)cTuyaResponse[15] + ((uint8_t)cTuyaResponse[14] << 8) + PROTOCOL_31_HEADER_SIZE);
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
			unsigned char *cPayload = &cTuyaResponse[PROTOCOL_31_HEADER_SIZE + sizeof(retcode)];
			int payloadSize = (int)(messageSize - PROTOCOL_31_HEADER_SIZE - sizeof(retcode) - MESSAGE_TRAILER_SIZE);

			result.append((const char *)cPayload, payloadSize + 1);
		}
		else
			result.append("{\"msg\":\"crc error\"}");

		bufferpos += messageSize;
	}
	return result;
}


/* private */ int tuyaAPI31::encode_base64( const unsigned char *input_str, int input_size, unsigned char *output_str)
{
	// Character set of base64 encoding scheme
	char char_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	
	int index, no_of_bits = 0, padding = 0, val = 0, count = 0, temp;
	int i, j, k = 0;
	
	// Loop takes 3 characters at a time from
	// input_str and stores it in val
	for (i = 0; i < input_size; i += 3)
		{
			val = 0, count = 0, no_of_bits = 0;

			for (j = i; j < input_size && j <= i + 2; j++)
			{
				// binary data of input_str is stored in val
				val = val << 8;
				
				// (A + 0 = A) stores character in val
				val = val | input_str[j];
				
				// calculates how many time loop
				// ran if "MEN" -> 3 otherwise "ON" -> 2
				count++;
			
			}

			no_of_bits = count * 8;

			// calculates how many "=" to append after output_str.
			padding = no_of_bits % 3;

			// extracts all bits from val (6 at a time)
			// and find the value of each block
			while (no_of_bits != 0)
			{
				// retrieve the value of each block
				if (no_of_bits >= 6)
				{
					temp = no_of_bits - 6;
					
					// binary of 63 is (111111) f
					index = (val >> temp) & 63;
					no_of_bits -= 6;		
				}
				else
				{
					temp = 6 - no_of_bits;
					
					// append zeros to right if bits are less than 6
					index = (val << temp) & 63;
					no_of_bits = 0;
				}
				output_str[k++] = char_set[index];
			}
	}

	// padding is done here
	for (i = 1; i <= padding; i++)
	{
		output_str[k++] = '=';
	}

	output_str[k] = '\0';

	return k;
 }


/* private */ std::string tuyaAPI31::make_md5_digest(const std::string &str)
{
	unsigned char *hash;
	unsigned int hash_len = EVP_MD_size(EVP_md5());
	EVP_MD_CTX *md5ctx;

	md5ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md5ctx, EVP_md5(), NULL);
	EVP_DigestUpdate(md5ctx, str.c_str(), str.size());
	hash = (unsigned char *)OPENSSL_malloc(hash_len);
	EVP_DigestFinal_ex(md5ctx, hash, &hash_len);
	EVP_MD_CTX_free(md5ctx);

	std::stringstream ss;

	for(unsigned int i = 0; i < hash_len; i++){
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( hash[i] );
	}
	return ss.str();
}


/* private */ bool tuyaAPI31::ResolveHost(const std::string &hostname, struct sockaddr_in& serv_addr)
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


bool tuyaAPI31::ConnectToDevice(const std::string &hostname, const int portnumber, uint8_t retries)
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


int tuyaAPI31::send(unsigned char* buffer, const unsigned int size)
{
#ifdef WIN32
	return ::send(m_sockfd, (char*)buffer, size, 0);
#else
	return write(m_sockfd, buffer, size);
#endif
}


int tuyaAPI31::receive(unsigned char* buffer, const unsigned int maxsize, const unsigned int minsize)
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

void tuyaAPI31::disconnect()
{
	close(m_sockfd);
	m_sockfd = 0;
}

