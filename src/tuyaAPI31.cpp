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


#define PROTOCOL_31_HEADER_SIZE 16
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 8

#include "tuyaAPI31.hpp"
#include <zlib.h>
#include <iomanip>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#ifdef DEBUG
#include <iostream>
#endif

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



