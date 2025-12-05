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


#define PROTOCOL_35_HEADER_SIZE 18
#define MESSAGE_PREFIX 0x00006699
#define MESSAGE_SUFFIX 0x00009966
#define MESSAGE_TRAILER_SIZE 4
#define GCM_TAG_SIZE 16
#define GCM_IV_SIZE 12

// v3.5 Session negotiation commands
#define SESS_KEY_NEG_START 3
#define SESS_KEY_NEG_RESP 4
#define SESS_KEY_NEG_FINISH 5

#include "tuyaAPI35.hpp"
#include <cstring>
#include <thread>

#ifdef DEBUG
#include <iostream>
#endif

tuyaAPI35::tuyaAPI35()
{
	m_protocol = Protocol::v35;
	m_session_established = false;
	m_seqno = 0;
}

void tuyaAPI35::SetEncryptionKey(const std::string &key)
{
	tuyaAPI::SetEncryptionKey(key);
	m_session_established = false;
	m_seqno = 0;
	random_bytes(m_local_nonce, 16);
}

int tuyaAPI35::BuildMessage35(unsigned char *buffer, uint32_t command, const std::string &payload,
                               const unsigned char *key, const unsigned char *iv)
{
	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_35_HEADER_SIZE);
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	// bytes 4-5 are unknown/reserved (set to 0)
	buffer[6] = (m_seqno & 0xFF000000) >> 24;
	buffer[7] = (m_seqno & 0x00FF0000) >> 16;
	buffer[8] = (m_seqno & 0x0000FF00) >> 8;
	buffer[9] = (m_seqno & 0x000000FF);
	buffer[10] = (command & 0xFF000000) >> 24;
	buffer[11] = (command & 0x00FF0000) >> 16;
	buffer[12] = (command & 0x0000FF00) >> 8;
	buffer[13] = (command & 0x000000FF);
	bufferpos += (int)PROTOCOL_35_HEADER_SIZE;

	// Calculate and set payload length before encryption (it's part of AAD)
	int payloadSize = (int)payload.length();
	int payload_len = GCM_IV_SIZE + payloadSize + GCM_TAG_SIZE;
	buffer[14] = (payload_len & 0xFF000000) >> 24;
	buffer[15] = (payload_len & 0x00FF0000) >> 16;
	buffer[16] = (payload_len & 0x0000FF00) >> 8;
	buffer[17] = (payload_len & 0x000000FF);

	// Copy IV to buffer
	memcpy(&buffer[bufferpos], iv, GCM_IV_SIZE);
	bufferpos += GCM_IV_SIZE;

	unsigned char* cEncryptedPayload = &buffer[bufferpos];
	int encryptedSize = 0;
	unsigned char tag[GCM_TAG_SIZE];

	// AAD is header bytes 4-17 (after prefix)
	if (aes_128_gcm_encrypt(key, iv, GCM_IV_SIZE,
	                        &buffer[4], PROTOCOL_35_HEADER_SIZE - 4,
	                        (unsigned char*)payload.c_str(), payloadSize,
	                        cEncryptedPayload, &encryptedSize,
	                        tag, GCM_TAG_SIZE) != 0)
		return -1;

	bufferpos += encryptedSize;

	// Append GCM tag
	memcpy(&buffer[bufferpos], tag, GCM_TAG_SIZE);
	bufferpos += GCM_TAG_SIZE;

	// Append suffix
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0x000000FF);

	return bufferpos;
}

int tuyaAPI35::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload, const std::string &encryption_key)
{
	if (!m_session_established)
		return -1;

	m_seqno++;

	// For control commands (7, 13), protocol 3.5 requires "3.5" prefix + 12 null bytes
	std::string payload = szPayload;
	if (command == TUYA_CONTROL || command == TUYA_CONTROL_NEW)
	{
		payload = "3.5";
		payload.append(12, '\0');
		payload.append(szPayload);
	}

	// Generate 12-byte IV
	unsigned char iv[GCM_IV_SIZE];
	random_bytes(iv, GCM_IV_SIZE);

#ifdef DEBUG
	std::cout << "dbg: Payload to encrypt (" << payload.length() << " bytes): " << payload << "\n";
#endif

	int result = BuildMessage35(buffer, command, payload, m_session_key, iv);

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


std::string tuyaAPI35::DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &encryption_key)
{
	if (!m_session_established)
		return "{\"msg\":\"session not established\"}";

	std::string result;
	int bufferpos = 0;

	while (bufferpos < size)
	{
		unsigned char* cTuyaResponse = &buffer[bufferpos];

		// Validate minimum size for this message
		if (bufferpos + PROTOCOL_35_HEADER_SIZE + MESSAGE_TRAILER_SIZE > size)
			break;

		int payload_len = (int)((uint8_t)cTuyaResponse[17] + ((uint8_t)cTuyaResponse[16] << 8) + ((uint8_t)cTuyaResponse[15] << 16) + ((uint8_t)cTuyaResponse[14] << 24));
		int messageSize = payload_len + PROTOCOL_35_HEADER_SIZE + MESSAGE_TRAILER_SIZE;

		// Validate we have the full message
		if (bufferpos + messageSize > size)
			break;

		// Extract IV (12 bytes after header)
		unsigned char iv[GCM_IV_SIZE];
		memcpy(iv, &cTuyaResponse[PROTOCOL_35_HEADER_SIZE], GCM_IV_SIZE);

		// Extract tag (16 bytes before suffix)
		unsigned char tag[GCM_TAG_SIZE];
		memcpy(tag, &cTuyaResponse[messageSize - MESSAGE_TRAILER_SIZE - GCM_TAG_SIZE], GCM_TAG_SIZE);

		// Encrypted payload is between IV and tag
		unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_35_HEADER_SIZE + GCM_IV_SIZE];
		int encryptedSize = payload_len - GCM_IV_SIZE - GCM_TAG_SIZE;

		unsigned char* cDecryptedPayload = new unsigned char[encryptedSize + 16];
		memset(cDecryptedPayload, 0, encryptedSize + 16);
		int decryptedSize = 0;

		// AAD is header bytes 4-19
		if (aes_128_gcm_decrypt(m_session_key, iv, GCM_IV_SIZE,
		                        &cTuyaResponse[4], PROTOCOL_35_HEADER_SIZE - 4,
		                        cEncryptedPayload, encryptedSize,
		                        tag, GCM_TAG_SIZE,
		                        cDecryptedPayload, &decryptedSize) == 0)
		{
			// Check for retcode at start of decrypted payload
			int json_start = 0;
			if (decryptedSize >= 4 && cDecryptedPayload[0] == 0 && cDecryptedPayload[1] == 0)
			{
				int retcode = (int)((uint8_t)cDecryptedPayload[3] + ((uint8_t)cDecryptedPayload[2] << 8));
				if (retcode != 0)
				{
					char cErrorMessage[50];
					sprintf(cErrorMessage, "{\"msg\":\"device returned error %d\"}", retcode);
					result.append(cErrorMessage);
					delete[] cDecryptedPayload;
					bufferpos += messageSize;
					continue;
				}
				json_start = 4;
			}

			// Strip protocol version header if present
			for (int i = json_start; i < decryptedSize - 1; i++)
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
		bufferpos += messageSize;
	}
	return result;
}

int tuyaAPI35::BuildSessionMessage(unsigned char *buffer)
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
		command = SESS_KEY_NEG_START;
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
		command = SESS_KEY_NEG_FINISH;
		payload = std::string((char*)rkey_hmac, 32);
	}
	else
	{
		// Session complete
		return 0;
	}

	// Use fixed IV for session messages (like tinytuya)
	unsigned char iv[GCM_IV_SIZE];
	memcpy(iv, "0123456789ab", GCM_IV_SIZE);

#ifdef DEBUG
	std::cout << "dbg: GCM encrypt - key len: " << m_device_key.length() << " key: ";
	for(size_t i=0; i<m_device_key.length(); ++i)
		printf("%.2x", (unsigned char)m_device_key[i]);
	std::cout << " AAD len: " << (PROTOCOL_35_HEADER_SIZE - 4)
	          << " payload len: " << payload.length() << " IV: ";
	for(int i=0; i<GCM_IV_SIZE; ++i)
		printf("%.2x", iv[i]);
	std::cout << "\n";
#endif

	int result = BuildMessage35(buffer, command, payload,
	                             (unsigned char*)m_device_key.c_str(), iv);

#ifdef DEBUG
	if (result > 0)
	{
		std::cout << "dbg: session message (size=" << result << "): ";
		for(int i=0; i<result; ++i)
			printf("%.2x", (uint8_t)buffer[i]);
		std::cout << "\n";
	}
#endif

	return result;
}


std::string tuyaAPI35::DecodeSessionMessage(unsigned char* buffer, const int size)
{
	// Validate minimum size
	if (size < PROTOCOL_35_HEADER_SIZE + MESSAGE_TRAILER_SIZE)
		return "";

	// Decrypt the session response
	std::string result;
	unsigned char* cTuyaResponse = buffer;
	int payload_len = (int)((uint8_t)cTuyaResponse[17] + ((uint8_t)cTuyaResponse[16] << 8) + ((uint8_t)cTuyaResponse[15] << 16) + ((uint8_t)cTuyaResponse[14] << 24));

	// Extract IV
	unsigned char iv[GCM_IV_SIZE];
	memcpy(iv, &cTuyaResponse[PROTOCOL_35_HEADER_SIZE], GCM_IV_SIZE);

	// Extract tag
	unsigned char tag[GCM_TAG_SIZE];
	int messageSize = payload_len + PROTOCOL_35_HEADER_SIZE + MESSAGE_TRAILER_SIZE;
	memcpy(tag, &cTuyaResponse[messageSize - MESSAGE_TRAILER_SIZE - GCM_TAG_SIZE], GCM_TAG_SIZE);

	// Encrypted payload
	unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_35_HEADER_SIZE + GCM_IV_SIZE];
	int encryptedSize = payload_len - GCM_IV_SIZE - GCM_TAG_SIZE;

	unsigned char* cDecryptedPayload = new unsigned char[encryptedSize + 16];
	memset(cDecryptedPayload, 0, encryptedSize + 16);
	int decryptedSize = 0;

	if (aes_128_gcm_decrypt((unsigned char*)m_device_key.c_str(), iv, GCM_IV_SIZE,
	                        &cTuyaResponse[4], PROTOCOL_35_HEADER_SIZE - 4,
	                        cEncryptedPayload, encryptedSize,
	                        tag, GCM_TAG_SIZE,
	                        cDecryptedPayload, &decryptedSize) == 0)
	{
		// Skip retcode if present
		int start = 0;
		if (decryptedSize >= 4 && cDecryptedPayload[0] == 0 && cDecryptedPayload[1] == 0)
			start = 4;

		result.append((char*)cDecryptedPayload + start, decryptedSize - start);
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

		// Encrypt XOR'd nonce with local_key using GCM (with local_nonce[:12] as IV)
		// Output is: nonce(12) + ciphertext(16) + tag(16), take bytes [12:28]
		unsigned char iv[GCM_IV_SIZE];
		memcpy(iv, m_local_nonce, GCM_IV_SIZE);

		unsigned char ciphertext[32];
		int ciphertextSize = 0;
		unsigned char tag[GCM_TAG_SIZE];

		if (aes_128_gcm_encrypt((unsigned char*)m_device_key.c_str(), iv, GCM_IV_SIZE,
		                        nullptr, 0,  // no AAD
		                        xor_nonce, 16,
		                        ciphertext, &ciphertextSize,
		                        tag, GCM_TAG_SIZE) != 0)
			return "";

		// Construct full output: nonce + ciphertext + tag
		unsigned char full_output[44];
		memcpy(full_output, iv, GCM_IV_SIZE);  // nonce
		memcpy(full_output + GCM_IV_SIZE, ciphertext, 16);  // ciphertext
		memcpy(full_output + GCM_IV_SIZE + 16, tag, GCM_TAG_SIZE);  // tag

		// Take bytes [12:28] which is the ciphertext
		memcpy(m_session_key, &full_output[12], 16);

#ifdef DEBUG
		std::cout << "dbg: Session key: ";
		for(int i=0; i<16; ++i)
			printf("%.2x", (uint8_t)m_session_key[i]);
		std::cout << "\n";
#endif
	}

	return result;
}
