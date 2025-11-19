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


#define PROTOCOL_34_HEADER_SIZE 16
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 36

#include "tuyaAPI34.hpp"
#include <cstring>
#include <thread>

#ifdef DEBUG
#include <iostream>
#endif

tuyaAPI34::tuyaAPI34()
{
	m_protocol = Protocol::v34;
	m_session_established = false;
	m_seqno = 0;
}

void tuyaAPI34::SetEncryptionKey(const std::string &key)
{
	tuyaAPI::SetEncryptionKey(key);
	m_session_established = false;
	m_seqno = 0;
	random_bytes(m_local_nonce, 16);
}

int tuyaAPI34::BuildMessage34(unsigned char *buffer, uint8_t command, const std::string &payload,
                               const unsigned char *key, int key_len)
{
	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_34_HEADER_SIZE);
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	buffer[4] = (m_seqno & 0xFF000000) >> 24;
	buffer[5] = (m_seqno & 0x00FF0000) >> 16;
	buffer[6] = (m_seqno & 0x0000FF00) >> 8;
	buffer[7] = (m_seqno & 0x000000FF);
	buffer[11] = command;
	bufferpos += (int)PROTOCOL_34_HEADER_SIZE;

	unsigned char* cEncryptedPayload = &buffer[bufferpos];
	int payloadSize = (int)payload.length();
	memset(cEncryptedPayload, 0, payloadSize + 16);
	int encryptedSize = 0;

	if (aes_128_ecb_encrypt(key, (unsigned char*)payload.c_str(), payloadSize, cEncryptedPayload, &encryptedSize) != 0)
		return -1;

	bufferpos += encryptedSize;
	unsigned char* cMessageTrailer = &buffer[bufferpos];

	int buffersize = bufferpos + MESSAGE_TRAILER_SIZE;
	buffer[14] = ((buffersize - PROTOCOL_34_HEADER_SIZE) & 0x0000FF00) >> 8;
	buffer[15] = (buffersize - PROTOCOL_34_HEADER_SIZE) & 0x000000FF;

	hmac_sha256(key, key_len, buffer, bufferpos, cMessageTrailer);

	cMessageTrailer[32] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	cMessageTrailer[33] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	cMessageTrailer[34] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	cMessageTrailer[35] = (MESSAGE_SUFFIX & 0x000000FF);

	return buffersize;
}

int tuyaAPI34::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload, const std::string &encryption_key)
{
	if (!m_session_established)
		return -1;

	m_seqno++;

	// For control commands (7, 13), protocol 3.4 requires "3.4" prefix + 12 null bytes
	std::string payload = szPayload;
	if (command == TUYA_CONTROL || command == TUYA_CONTROL_NEW)
	{
		payload = "3.4";
		payload.append(12, '\0');
		payload.append(szPayload);
	}

#ifdef DEBUG
	std::cout << "dbg: Payload to encrypt (" << payload.length() << " bytes): " << payload << "\n";
#endif

	int result = BuildMessage34(buffer, command, payload, m_session_key, 16);

#ifdef DEBUG
	if (result > 0)
	{
		std::cout << "dbg: normal message (size=" << result << "): ";
		for(int i=0; i<result; ++i)
			printf("%.2x", (uint8_t)buffer[i]);
		std::cout << "\n";
	}
#endif

	return result;
}


std::string tuyaAPI34::DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &encryption_key)
{
	if (!m_session_established)
		return "{\"msg\":\"session not established\"}";

	std::string result;
	int bufferpos = 0;

	while (bufferpos < size)
	{
		unsigned char* cTuyaResponse = &buffer[bufferpos];
		int messageSize = (int)((uint8_t)cTuyaResponse[15] + ((uint8_t)cTuyaResponse[14] << 8) + PROTOCOL_34_HEADER_SIZE);
		int retcode = (int)((uint8_t)cTuyaResponse[19] + ((uint8_t)cTuyaResponse[18] << 8));

		if (retcode != 0)
		{
			char cErrorMessage[50];
			sprintf(cErrorMessage, "{\"msg\":\"device returned error %d\"}", retcode);
			result.append(cErrorMessage);
			bufferpos += messageSize;
			continue;
		}

		// For v3.4, verify HMAC instead of CRC
		unsigned char hmac_sent[32];
		memcpy(hmac_sent, &cTuyaResponse[messageSize - 36], 32);

		unsigned char hmac_calc[32];
		hmac_sha256(m_session_key, 16, cTuyaResponse, messageSize - 36, hmac_calc);

		if (memcmp(hmac_sent, hmac_calc, 32) == 0)
		{
			unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_34_HEADER_SIZE + sizeof(retcode)];
			int payloadSize = (int)(messageSize - PROTOCOL_34_HEADER_SIZE - sizeof(retcode) - 36);  // 36 = 32 HMAC + 4 suffix

			unsigned char* cDecryptedPayload = new unsigned char[payloadSize + 16];
			memset(cDecryptedPayload, 0, payloadSize + 16);
			int decryptedSize = 0;

			if (aes_128_ecb_decrypt(m_session_key, cEncryptedPayload, payloadSize, cDecryptedPayload, &decryptedSize) == 0)
			{
				// Strip protocol version header (e.g., "3.4" followed by binary data)
				// Look for the start of JSON data
				int json_start = 0;
				for (int i = 0; i < decryptedSize - 1; i++)
				{
					if (cDecryptedPayload[i] == '{')
					{
						json_start = i;
						break;
					}
				}

				result.append((char*)cDecryptedPayload + json_start, decryptedSize - json_start);
			}
			else
			{
				result.append("{\"msg\":\"error decrypting payload\"}");
			}

			delete[] cDecryptedPayload;
		}
		else
			result.append("{\"msg\":\"crc error\"}");

		bufferpos += messageSize;
	}
	return result;
}

int tuyaAPI34::BuildSessionMessage(unsigned char *buffer)
{
	uint8_t command;
	std::string payload;

	if (m_seqno == 0)
	{
		// Send first message: local nonce
#ifdef DEBUG
		std::cout << "dbg: Starting session negotiation\n";
#endif
		m_seqno = 1;
		command = 3;
		payload = std::string((char*)m_local_nonce, 16);
	}
	else if (m_seqno == 1)
	{
		// After receiving response, send second message
		unsigned char rkey_hmac[32];
		hmac_sha256((unsigned char*)m_device_key.c_str(), m_device_key.length(),
		            m_remote_nonce, 16, rkey_hmac);

		m_seqno = 2;
		m_session_established = true;
		command = 5;
		payload = std::string((char*)rkey_hmac, 32);
	}
	else
	{
		// Session complete
		return 0;
	}

	return BuildMessage34(buffer, command, payload,
	                      (unsigned char*)m_device_key.c_str(), m_device_key.length());
}


std::string tuyaAPI34::DecodeSessionMessage(unsigned char* buffer, const int size)
{
	// Decrypt the session response
	std::string result;
	unsigned char* cTuyaResponse = buffer;
	int messageSize = (int)((uint8_t)cTuyaResponse[15] + ((uint8_t)cTuyaResponse[14] << 8) + PROTOCOL_34_HEADER_SIZE);

	// Session messages have a 4-byte retcode after the header
	unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_34_HEADER_SIZE + 4];
	int payloadSize = (int)(messageSize - PROTOCOL_34_HEADER_SIZE - 4 - MESSAGE_TRAILER_SIZE);

	unsigned char* cDecryptedPayload = new unsigned char[payloadSize + 16];
	memset(cDecryptedPayload, 0, payloadSize + 16);
	int decryptedSize = 0;

	if (aes_128_ecb_decrypt((unsigned char*)m_device_key.c_str(), cEncryptedPayload, payloadSize, cDecryptedPayload, &decryptedSize) == 0)
	{
		result.append((char*)cDecryptedPayload, decryptedSize);
	}
	else
	{
		result.append("{\"msg\":\"error decrypting payload\"}");
	}

	delete[] cDecryptedPayload;

	// Process the decrypted response based on state
	if (m_seqno == 1 && result.length() >= 48)
	{
		// Extract remote_nonce (first 16 bytes)
		memcpy(m_remote_nonce, result.c_str(), 16);

		// Verify HMAC(local_key, local_nonce) matches bytes 16-47
		unsigned char hmac_check[32];
		hmac_sha256((unsigned char*)m_device_key.c_str(), m_device_key.length(),
		            m_local_nonce, 16, hmac_check);

		if (memcmp(hmac_check, (unsigned char*)result.c_str() + 16, 32) != 0)
		{
#ifdef DEBUG
			std::cout << "dbg: HMAC verification failed!\n";
#endif
			return "";
		}

		// XOR local and remote nonces
		unsigned char xor_nonce[16];
		for (int i = 0; i < 16; i++)
			xor_nonce[i] = m_local_nonce[i] ^ m_remote_nonce[i];

		// Encrypt XOR'd nonce with local_key using ECB to get session key
		int outlen;
		if (aes_128_ecb_encrypt((unsigned char*)m_device_key.c_str(), xor_nonce, 16, m_session_key, &outlen) != 0)
			return "";

#ifdef DEBUG
		std::cout << "dbg: Session key: ";
		for(int i=0; i<16; ++i)
			printf("%.2x", (uint8_t)m_session_key[i]);
		std::cout << "\n";
#endif
	}

	return result;
}



