/*
 *  Client interface for local Tuya device access
 *
 *  API 3.3 module
 *
 *
 *  Copyright 2022-2026 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#ifndef WITHOUT_API33


#define PROTOCOL_33_HEADER_SIZE 16
#define PROTOCOL_33_EXTRA_HEADER_SIZE 15
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 8

#include "tuyaAPI33.hpp"
#include <cstring>
#include "crypt/crc32.hpp"
#include "crypt/aes_128_ecb.hpp"

#ifdef DEBUG
#include <iostream>
#endif


tuyaAPI33::tuyaAPI33()
{
	m_protocol = Protocol::v33;
	m_seqno = 0;
}


int tuyaAPI33::BuildTuyaMessage(unsigned char *cMessageBuffer, const uint8_t command, const std::string &szPayload, const std::string &szEncryptionKey)
{
	int bufferpos = 0;
	memset(cMessageBuffer, 0, PROTOCOL_33_HEADER_SIZE);
	// set message prefix
	cMessageBuffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	cMessageBuffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	cMessageBuffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	cMessageBuffer[3] = (MESSAGE_PREFIX & 0x000000FF);

	// set message sequence number
	m_seqno++;
	cMessageBuffer[4] = (m_seqno & 0xFF000000) >> 24;
	cMessageBuffer[5] = (m_seqno & 0x00FF0000) >> 16;
	cMessageBuffer[6] = (m_seqno & 0x0000FF00) >> 8;
	cMessageBuffer[7] = (m_seqno & 0x000000FF);

	// set command code at int32 @msg[8] (single byte value @msg[11])
	cMessageBuffer[11] = command;
	bufferpos += (int)PROTOCOL_33_HEADER_SIZE;

	if ((command != TUYA_DP_QUERY) && (command != TUYA_UPDATEDPS))
	{
		// add the protocol 3.3 secondary header
		unsigned char* extraHeader = &cMessageBuffer[bufferpos];
		memset(extraHeader, 0, PROTOCOL_33_EXTRA_HEADER_SIZE);
		strcpy((char*)extraHeader, "3.3");
		bufferpos += PROTOCOL_33_EXTRA_HEADER_SIZE;
	}

	unsigned char* cEncryptedPayload = &cMessageBuffer[bufferpos];
	int payloadSize = (int)szPayload.length();
	memset(cEncryptedPayload, 0, payloadSize + 16);
	int encryptedSize = 0;
	if (!aes_128_ecb_encrypt((unsigned char*)szEncryptionKey.c_str(), (unsigned char*)szPayload.c_str(), payloadSize, cEncryptedPayload, &encryptedSize))
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
	unsigned char* cMessageTrailer = &cMessageBuffer[bufferpos];

	// update message size in int32 @cMessageBuffer[12]
	int buffersize = bufferpos + MESSAGE_TRAILER_SIZE;
	cMessageBuffer[14] = ((buffersize - PROTOCOL_33_HEADER_SIZE) & 0x0000FF00) >> 8;
	cMessageBuffer[15] = (buffersize - PROTOCOL_33_HEADER_SIZE) & 0x000000FF;

	// calculate CRC
	unsigned long crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, cMessageBuffer, bufferpos) & 0xFFFFFFFF;

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
		printf("%.2x", (uint8_t)cMessageBuffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}


std::string tuyaAPI33::DecodeTuyaMessage(unsigned char *cMessageBuffer, const int buffersize, const std::string &szEncryptionKey)
{
	std::string result;

	int bufferpos = 0;

	while (bufferpos < buffersize)
	{
		unsigned char* cTuyaResponse = &cMessageBuffer[bufferpos];
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
			if (aes_128_ecb_decrypt((unsigned char*)szEncryptionKey.c_str(), cEncryptedPayload, payloadSize, cDecryptedPayload, &decryptedSize))
				result.append((char*)cDecryptedPayload);
			else
				result.append("{\"msg\":\"error decrypting payload\"}");

		}
		else
			result.append("{\"msg\":\"crc error\"}");

		bufferpos += messageSize;
	}
	return result;
}

#endif // WITHOUT_API33

