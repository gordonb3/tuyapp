/*
 *  Client interface for local Tuya device access
 *
 *  API 3.5 module
 *
 *
 *  Copyright 2022-2026 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#ifndef WITHOUT_API35

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

#include "crypt/aes_128_gcm.hpp"
#include "crypt/hmac_sha256.hpp"
#include "crypt/rand.hpp"

#ifdef DEBUG
#include <iostream>
#endif

tuyaAPI35::tuyaAPI35()
{
	m_protocol = Protocol::v35;
	m_seqno = 0;
	random_bytes(m_local_nonce, 16);
}

int tuyaAPI35::BuildTuyaMessage(unsigned char *cMessageBuffer, const uint8_t command, const std::string &szPayload, const std::string &szEncryptionKey)
{
	if (m_sessionState != Tuya::Session::ESTABLISHED)
	{
		// need command to be one of the session negotiation commands
		switch (command)
		{
			case SESS_KEY_NEG_START:
			case SESS_KEY_NEG_RESP:
			case SESS_KEY_NEG_FINISH:
				break;
			default:
				return -1;
		}
	}

	m_seqno++;
	unsigned char local_key[16];

	// For control commands (7, 13), protocol 3.5 requires "3.5" prefix + 12 null bytes
	std::string payload = szPayload;
	if (command == TUYA_CONTROL || command == TUYA_CONTROL_NEW)
	{
		payload = "3.5";
		payload.append(12, '\0');
		payload.append(szPayload);
	}

	int bufferpos = 0;
	memset(cMessageBuffer, 0, PROTOCOL_35_HEADER_SIZE);
	cMessageBuffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	cMessageBuffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	cMessageBuffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	cMessageBuffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	// bytes 4-7 are unknown/reserved (set to 0)
	// bytes 4-5 are unknown/reserved (set to 0)
	cMessageBuffer[6] = (m_seqno & 0xFF000000) >> 24;
	cMessageBuffer[7] = (m_seqno & 0x00FF0000) >> 16;
	cMessageBuffer[8] = (m_seqno & 0x0000FF00) >> 8;
	cMessageBuffer[9] = (m_seqno & 0x000000FF);

/*
	// command is only an 8 bit int and we already initialized the higher bits to 0
	cMessageBuffer[10] = (command & 0xFF000000) >> 24;
	cMessageBuffer[11] = (command & 0x00FF0000) >> 16;
	cMessageBuffer[12] = (command & 0x0000FF00) >> 8;
*/
	cMessageBuffer[13] = (command & 0x000000FF);
	bufferpos += (int)PROTOCOL_35_HEADER_SIZE;

#ifdef DEBUG
	if (m_sessionState == Tuya::Session::ESTABLISHED)
		std::cout << "dbg: Payload to encrypt (" << payload.length() << " bytes): " << payload << "\n";
#endif

	// Calculate and set payload length before encryption (it's part of AAD)
	int payloadSize = (int)payload.length();
	int payload_len = GCM_IV_SIZE + payloadSize + GCM_TAG_SIZE;
	cMessageBuffer[14] = (payload_len & 0xFF000000) >> 24;
	cMessageBuffer[15] = (payload_len & 0x00FF0000) >> 16;
	cMessageBuffer[16] = (payload_len & 0x0000FF00) >> 8;
	cMessageBuffer[17] = (payload_len & 0x000000FF);


	// Generate 12-byte IV
	unsigned char iv[GCM_IV_SIZE];
	if (m_sessionState != Tuya::Session::ESTABLISHED)
	{
		memcpy(iv, "0123456789ab", GCM_IV_SIZE);
		memcpy(&local_key, szEncryptionKey.c_str(), 16);
	}
	else
	{
		random_bytes(iv, GCM_IV_SIZE);
		memcpy(&local_key, m_session_key, 16);
	}

	// Copy IV to cMessageBuffer
	memcpy(&cMessageBuffer[bufferpos], iv, GCM_IV_SIZE);
	bufferpos += GCM_IV_SIZE;

	unsigned char* cEncryptedPayload = &cMessageBuffer[bufferpos];
	int encryptedSize = 0;
	unsigned char tag[GCM_TAG_SIZE];

	// AAD is header bytes 4-17 (after prefix)
	if (!aes_128_gcm_encrypt(local_key, iv, GCM_IV_SIZE, &cMessageBuffer[4], PROTOCOL_35_HEADER_SIZE - 4, (unsigned char*)payload.c_str(), payloadSize, cEncryptedPayload, &encryptedSize, tag, GCM_TAG_SIZE))
		return -1;

	bufferpos += encryptedSize;

	// Append GCM tag
	memcpy(&cMessageBuffer[bufferpos], tag, GCM_TAG_SIZE);
	bufferpos += GCM_TAG_SIZE;

	// Append suffix
	cMessageBuffer[bufferpos++] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	cMessageBuffer[bufferpos++] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	cMessageBuffer[bufferpos++] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	cMessageBuffer[bufferpos++] = (MESSAGE_SUFFIX & 0x000000FF);

	int buffersize = bufferpos;

#ifdef DEBUG
	std::cout << "dbg: normal message (size=" << buffersize << "): ";
	for(int i=0; i<buffersize; ++i)
		printf("%.2x", (uint8_t)cMessageBuffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}


std::string tuyaAPI35::DecodeTuyaMessage(unsigned char *cMessageBuffer, const int buffersize, const std::string &szEncryptionKey)
{
	unsigned char local_key[16];
	if (m_sessionState != Tuya::Session::ESTABLISHED)
		memcpy(&local_key, szEncryptionKey.c_str(), 16);
	else
		memcpy(&local_key, m_session_key, 16);

	std::string result;
	int bufferpos = 0;

	while (bufferpos < buffersize)
	{
		unsigned char* cTuyaResponse = &cMessageBuffer[bufferpos];

		// Validate minimum size for this message
		if (bufferpos + PROTOCOL_35_HEADER_SIZE + MESSAGE_TRAILER_SIZE > buffersize)
			break;

		int payload_len = (int)((uint8_t)cTuyaResponse[17] + ((uint8_t)cTuyaResponse[16] << 8) + ((uint8_t)cTuyaResponse[15] << 16) + ((uint8_t)cTuyaResponse[14] << 24));
		int messageSize = payload_len + PROTOCOL_35_HEADER_SIZE + MESSAGE_TRAILER_SIZE;

		// Validate we have the full message
		if (bufferpos + messageSize > buffersize)
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
		if (aes_128_gcm_decrypt(local_key, iv, GCM_IV_SIZE, &cTuyaResponse[4], PROTOCOL_35_HEADER_SIZE - 4, cEncryptedPayload, encryptedSize, tag, GCM_TAG_SIZE, cDecryptedPayload, &decryptedSize))
		{
			if (m_sessionState == Tuya::Session::ESTABLISHED)
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
				// Skip retcode if present
				int start = 0;
				if (decryptedSize >= 4 && cDecryptedPayload[0] == 0 && cDecryptedPayload[1] == 0)
					start = 4;

				result.append((char*)cDecryptedPayload + start, decryptedSize - start);
			}
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


bool tuyaAPI35::NegotiateSessionStart(const std::string &szEncryptionKey)
{
	m_sessionState = Tuya::Session::STARTING;

#ifdef DEBUG
	std::cout << "dbg: Starting session negotiation\n";
#endif
	m_seqno = 0;
	unsigned char cMessageBuffer[128];
	uint8_t command = SESS_KEY_NEG_START;
	std::string szPayload = std::string((char*)m_local_nonce, 16);
	int msgSize = BuildTuyaMessage(cMessageBuffer, command, szPayload, szEncryptionKey);
	if (msgSize < 0 || send(cMessageBuffer, msgSize) < 0)
	{
#ifdef DEBUG
		std::cout << "dbg: Failed to send session message 1\n";
#endif
		return false;
	}
	return true;
}


bool tuyaAPI35::NegotiateSessionFinalize(unsigned char *cMessageBuffer, const int buffersize, const std::string &szEncryptionKey)
{
	m_sessionState = Tuya::Session::FINALIZING;

	std::string response = DecodeTuyaMessage(cMessageBuffer, buffersize, szEncryptionKey);
	if (response.length() < 48)
	{
#ifdef DEBUG
		std::cout << "dbg: Response too short: " << response.length() << " bytes\n";
#endif
		return false;
	}

	// Extract remote_nonce (first 16 bytes)
	memcpy(m_remote_nonce, response.c_str(), 16);

	// Verify HMAC(local_key, local_nonce) matches bytes 16-47
	unsigned char hmac_check[32];
	hmac_sha256((unsigned char*)szEncryptionKey.c_str(), szEncryptionKey.length(), m_local_nonce, 16, hmac_check);

	if (memcmp(hmac_check, (unsigned char*)response.c_str() + 16, 32) != 0)
	{
#ifdef DEBUG
		std::cout << "dbg: HMAC verification failed!\n";
#endif
		return false;
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

	if (!aes_128_gcm_encrypt((unsigned char*)szEncryptionKey.c_str(), iv, GCM_IV_SIZE, nullptr, 0, xor_nonce, 16, ciphertext, &ciphertextSize, tag, GCM_TAG_SIZE))
		return false;

	// Construct full output: nonce + ciphertext + tag
	unsigned char full_output[44];
	memcpy(full_output, iv, GCM_IV_SIZE);  // nonce
	memcpy(full_output + GCM_IV_SIZE, ciphertext, 16);  // ciphertext
	memcpy(full_output + GCM_IV_SIZE + 16, tag, GCM_TAG_SIZE);  // tag

	// Take bytes [12:28] which is the ciphertext
	memcpy(m_session_key, &full_output[12], 16);

#ifdef DEBUG
	std::cout << "dbg: HMAC verification passed\n";
	std::cout << "dbg: remote_nonce: ";
	for(int i=0; i<16; ++i)
		printf("%.2x", m_remote_nonce[i]);
	std::cout << "\n";
	std::cout << "dbg: Session key: ";
	for(int i=0; i<16; ++i)
		printf("%.2x", (uint8_t)m_session_key[i]);
	std::cout << "\n";
#endif

	// Second session message: send HMAC of remote nonce
	unsigned char rkey_hmac[32];
	hmac_sha256((unsigned char*)szEncryptionKey.c_str(), szEncryptionKey.length(), m_remote_nonce, 16, rkey_hmac);
	uint8_t command = SESS_KEY_NEG_FINISH;
	std::string szPayload = std::string((char*)rkey_hmac, 32);
	int msgSize = BuildTuyaMessage(cMessageBuffer, command, szPayload, szEncryptionKey);
	if (msgSize < 0 || send(cMessageBuffer, msgSize) < 0)
	{
#ifdef DEBUG
		std::cout << "dbg: Failed to send session message 2\n";
#endif
		return false;
	}

#ifdef DEBUG
	std::cout << "dbg: Session negotiation complete\n";
#endif

	m_sessionState = Tuya::Session::ESTABLISHED;
	return true;
}


// deprecated - only works when blocking mode communication is enabled
bool tuyaAPI35::NegotiateSession(const std::string &szEncryptionKey)
{
	NegotiateSessionStart(szEncryptionKey);
	unsigned char cMessageBuffer[1024];
	int recvSize = receive(cMessageBuffer, sizeof(cMessageBuffer), 0);
	if (recvSize < 0)
	{
#ifdef DEBUG
		std::cout << "dbg: Failed to receive session response\n";
#endif
		return false;
	}

#ifdef DEBUG
	std::cout << "dbg: Received " << recvSize << " bytes\n";
#endif

	bool result = NegotiateSessionFinalize(cMessageBuffer, recvSize, szEncryptionKey);

#ifdef DEBUG
	// There appears to be no response from the device to indicate either pass or success
	// Keep this block to run further investigation
	recvSize = receive(cMessageBuffer, sizeof(cMessageBuffer), 0);
	std::cout << "got response : ";
	for(int i=0; i<recvSize; ++i)
		printf("%.2x", (uint8_t)cMessageBuffer[i]);
	std::cout << "\n";
#endif
	return result;
}

#endif // WITHOUT_API35

