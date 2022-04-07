/*
 * client interface for local Tuya device access
 *
 *  Copyright 2017-2020 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */


//#define DEBUG

#include "tuyaAPI33.hpp"
#include "AES.h"
#include <netdb.h>
#include <zlib.h>
#include <sstream>
#include <thread>
#include <chrono>


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
	close(sockfd);
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

	AES aes(AESKeyLength::AES_128);
	unsigned char *out = aes.EncryptECB((unsigned char*)payload.c_str(), payload_len, (unsigned char*)encryption_key.c_str());

#ifdef DEBUG
	std::cout << "dbg: encrypted payload: ";
	for(int i=0; i<payload_len; ++i)
		printf("%.2x", (uint8_t)out[i]);
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
	bcopy(out, (char*)&buffer[payload_pos], payload_len);
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

			AES aes(AESKeyLength::AES_128);
			unsigned char *out = aes.DecryptECB(encryptedpayload, payload_len, (unsigned char*)encryption_key.c_str());
			// trim padding chars from decrypted payload
			uint8_t padding = out[payload_len - 1];
			if (padding <= 16)
				out[payload_len - padding] = 0;

			result.append((char*)out);
		}
		else
			result.append("{\"msg\":\"crc error\"}");

		message_start += message_size;
	}
	return result;
}


bool tuyaAPI33::ConnectToDevice(const std::string &hostname, const int portnumber, uint8_t retries)
{
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
#ifdef DEBUG
		exit_error("ERROR opening socket");
#else
		return false;
#endif
	server = gethostbyname(hostname.c_str());
	if (server == NULL)
#ifdef DEBUG
		exit_error("ERROR, no such host");
#else
		return false;
#endif
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr,
		 (char *)&serv_addr.sin_addr.s_addr,
		 server->h_length);
	serv_addr.sin_port = htons(portnumber);

	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

	for (uint8_t i = 0; i < retries; i++)
	{
		int res = connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
		if (res == 0)
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
	return write(sockfd, buffer, size + sizeof(MESSAGE_SEND_HEADER) + sizeof(MESSAGE_SEND_TRAILER));
}

int tuyaAPI33::receive(unsigned char* buffer, const unsigned int maxsize, const unsigned int minsize)
{
	unsigned int numbytes = (unsigned int)read(sockfd, buffer, maxsize);
	while (numbytes <= minsize)
	{
		// after sending a device state change command tuya devices send an empty `ack` reply first
		// wait for 100ms to allow device to commit and then retry for the answer that we want
#ifdef DEBUG
		std::cout << "{\"ack\":true}\n";
#endif
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		numbytes = (unsigned int)read(sockfd, buffer, maxsize);
	}
	return (int)numbytes;
}





