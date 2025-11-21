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


#define PROTOCOL_33_HEADER_SIZE 16
#define PROTOCOL_33_EXTRA_HEADER_SIZE 15
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 8

#include "tuyaAPI33.hpp"
#include <zlib.h>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef DEBUG
#include <iostream>
#endif


tuyaAPI33::tuyaAPI33()
{
	m_protocol = Protocol::v33;
	m_seqno = 0;
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

	// set message sequence number
	m_seqno++;
	buffer[4] = (m_seqno & 0xFF000000) >> 24;
	buffer[5] = (m_seqno & 0x00FF0000) >> 16;
	buffer[6] = (m_seqno & 0x0000FF00) >> 8;
	buffer[7] = (m_seqno & 0x000000FF);

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

