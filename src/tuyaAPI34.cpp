/*
 *  Client interface for local Tuya device access
 *
 *  API 3.4 module
 *
 *
 *  Copyright 2022-2026 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#ifndef WITHOUT_API34


#define PROTOCOL_34_HEADER_SIZE 16
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 36

#define SESS_KEY_NEG_START 3
#define SESS_KEY_NEG_RESP 4
#define SESS_KEY_NEG_FINISH 5

#include "tuyaAPI34.hpp"
#include <cstring>
#include <thread>

#include "crypt/aes_128_ecb.hpp"
#include "crypt/hmac_sha256.hpp"
#include "crypt/rand.hpp"


#ifdef DEBUG
#include <iostream>
#endif


tuyaAPI34::tuyaAPI34()
{
	m_protocol = Protocol::v34;
	m_sessionState = Tuya::Session::INVALID;
	m_seqno = 0;
}


int tuyaAPI34::BuildTuyaMessage(unsigned char *cMessageBuffer, const uint8_t command, const std::string &szPayload, const std::string &szEncryptionKey)
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
	if (m_sessionState != Tuya::Session::ESTABLISHED)
		memcpy(&local_key, szEncryptionKey.c_str(), 16);
	else
		memcpy(&local_key, m_session_key, 16);

	// For control commands (7, 13), protocol 3.4 requires "3.4" prefix + 12 null bytes
	std::string payload = szPayload;
	if (command == TUYA_CONTROL || command == TUYA_CONTROL_NEW)
	{
		payload = "3.4";
		payload.append(12, '\0');
		payload.append(szPayload);
	}

	int bufferpos = 0;
	memset(cMessageBuffer, 0, PROTOCOL_34_HEADER_SIZE);
	cMessageBuffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	cMessageBuffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	cMessageBuffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	cMessageBuffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	cMessageBuffer[4] = (m_seqno & 0xFF000000) >> 24;
	cMessageBuffer[5] = (m_seqno & 0x00FF0000) >> 16;
	cMessageBuffer[6] = (m_seqno & 0x0000FF00) >> 8;
	cMessageBuffer[7] = (m_seqno & 0x000000FF);
	cMessageBuffer[11] = command;
	bufferpos += (int)PROTOCOL_34_HEADER_SIZE;

#ifdef DEBUG
	std::cout << "dbg: Payload to encrypt (" << payload.length() << " bytes): " << payload << "\n";
#endif

	unsigned char* cEncryptedPayload = &cMessageBuffer[bufferpos];
	int payloadSize = (int)payload.length();
	memset(cEncryptedPayload, 0, payloadSize + 16);
	int encryptedSize = 0;
	if (!aes_128_ecb_encrypt(local_key, (unsigned char*)szPayload.c_str(), payloadSize, cEncryptedPayload, &encryptedSize))
	{
		// encryption failure
		return -1;
	}

	bufferpos += encryptedSize;
	unsigned char* cMessageTrailer = &cMessageBuffer[bufferpos];

	int buffersize = bufferpos + MESSAGE_TRAILER_SIZE;
	cMessageBuffer[14] = ((buffersize - PROTOCOL_34_HEADER_SIZE) & 0x0000FF00) >> 8;
	cMessageBuffer[15] = (buffersize - PROTOCOL_34_HEADER_SIZE) & 0x000000FF;

	// Calculate HMAC-SHA256 of header + encrypted payload
	hmac_sha256(local_key, 16, cMessageBuffer, bufferpos, cMessageTrailer);

	cMessageTrailer[32] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	cMessageTrailer[33] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	cMessageTrailer[34] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	cMessageTrailer[35] = (MESSAGE_SUFFIX & 0x000000FF);

#ifdef DEBUG
	std::cout << "dbg: normal message (size=" << buffersize << "): ";
	for(int i=0; i<buffersize; ++i)
		printf("%.2x", (uint8_t)cMessageBuffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}


std::string tuyaAPI34::DecodeTuyaMessage(unsigned char* cMessageBuffer, const int buffersize, const std::string &szEncryptionKey)
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
		int messageSize = (int)((uint8_t)cTuyaResponse[15] + ((uint8_t)cTuyaResponse[14] << 8) + PROTOCOL_34_HEADER_SIZE);

		if (m_sessionState != Tuya::Session::ESTABLISHED)
		{
			// verify return code
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
			memcpy(hmac_sent, &cTuyaResponse[messageSize - MESSAGE_TRAILER_SIZE], 32);

			unsigned char hmac_calc[32];
			hmac_sha256(local_key, 16, cTuyaResponse, messageSize - MESSAGE_TRAILER_SIZE, hmac_calc);
			if (memcmp(hmac_sent, hmac_calc, 32) != 0)
			{
				result.append("{\"msg\":\"hmac error\"}");
				bufferpos += messageSize;
				continue;
			}
		}

		unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_34_HEADER_SIZE + sizeof(int)];
		int payloadSize = (int)(messageSize - PROTOCOL_34_HEADER_SIZE - sizeof(int) - MESSAGE_TRAILER_SIZE);

		unsigned char* cDecryptedPayload = new unsigned char[payloadSize + 16];
		memset(cDecryptedPayload, 0, payloadSize + 16);
		int decryptedSize = 0;
		if (aes_128_ecb_decrypt(local_key, cEncryptedPayload, payloadSize, cDecryptedPayload, &decryptedSize))
		{
			if (m_sessionState == Tuya::Session::ESTABLISHED)
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
				result.append((char*)cDecryptedPayload, decryptedSize);
			}
		}
		else
			result.append("{\"msg\":\"error decrypting payload\"}");

		delete[] cDecryptedPayload;
		bufferpos += messageSize;
	}
	return result;
}


bool tuyaAPI34::ConnectToDevice(const std::string &hostname)
{
	// Use base class connection
	if (!tuyaAPI::ConnectToDevice(hostname))
		return false;

	// Protocol 3.4 requires session negotiation
	// Session will be negotiated on first message
	m_sessionState = Tuya::Session::INVALID;
	m_seqno = 0;
	return true;
}


bool tuyaAPI34::NegotiateSessionStart(const std::string &szEncryptionKey)
{
	m_sessionState = Tuya::Session::STARTING;

#ifdef DEBUG
	std::cout << "dbg: Starting session negotiation\n";
#endif
	unsigned char cMessageBuffer[128];
	random_bytes(m_local_nonce, 16);
	m_seqno = 0;

	uint8_t command = SESS_KEY_NEG_START;
	std::string szPayload = std::string((char*)m_local_nonce, 16);
	int msgSize = BuildTuyaMessage(cMessageBuffer, command, szPayload, szEncryptionKey);
	if (msgSize < 0)
	{
#ifdef DEBUG
		std::cout << "dbg: Failed to build session message 1\n";
#endif
		m_sessionState = Tuya::Session::INVALID;
		return false;
	}

	if (send(cMessageBuffer, msgSize) < 0)
	{
#ifdef DEBUG
		std::cout << "dbg: Failed to send session message 1\n";
#endif
		m_sessionState = Tuya::Session::INVALID;
		return false;
	}
	return true;
}


bool tuyaAPI34::NegotiateSessionFinalize(unsigned char *cMessageBuffer, const int buffersize, const std::string &szEncryptionKey)
{
	m_sessionState = Tuya::Session::FINALIZING;

	std::string response = DecodeTuyaMessage(cMessageBuffer, buffersize, szEncryptionKey);
	if (response.length() < 48)
	{
#ifdef DEBUG
		std::cout << "dbg: Response too short: " << response.length() << " bytes\n";
#endif
		m_sessionState = Tuya::Session::INVALID;
		return false;
	}

#ifdef DEBUG
	std::cout << "dbg: Decrypted response (" << response.length() << " bytes): ";
	for(size_t i = 0; i < response.length() && i < 48; ++i)
		printf("%.2x", (unsigned char)response[i]);
	std::cout << "\n";
#endif

	// Extract remote_nonce (first 16 bytes) - it's ASCII hex string, use it directly
	memcpy(m_remote_nonce, response.c_str(), 16);

	// Verify HMAC(szEncryptionKey, local_nonce) matches bytes 16-47
	unsigned char hmac_check[32];
	hmac_sha256((unsigned char*)szEncryptionKey.c_str(), szEncryptionKey.length(), m_local_nonce, 16, hmac_check);

	if (memcmp(hmac_check, (unsigned char*)response.c_str() + 16, 32) != 0)
	{
#ifdef DEBUG
		std::cout << "dbg: HMAC verification failed!\n";
		std::cout << "dbg: Expected: ";
		for(int i=0; i<32; ++i) printf("%.2x", hmac_check[i]);
		std::cout << "\ndbg: Got: ";
		for(int i=0; i<32; ++i) printf("%.2x", (unsigned char)response[16+i]);
		std::cout << "\n";
#endif
		m_sessionState = Tuya::Session::INVALID;
		return false;
	}

#ifdef DEBUG
	std::cout << "dbg: HMAC verification passed\n";
	std::cout << "dbg: remote_nonce: ";
	for(int i=0; i<16; ++i) printf("%.2x", m_remote_nonce[i]);
	std::cout << "\n";
#endif

	// XOR local and remote nonces
	unsigned char xor_nonce[16];
	for (int i = 0; i < 16; i++)
		xor_nonce[i] = m_local_nonce[i] ^ m_remote_nonce[i];

	// Encrypt XOR'd nonce with szEncryptionKey using ECB to get session key
	try
	{
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		int outlen;
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)szEncryptionKey.c_str(), nullptr);
		EVP_EncryptUpdate(ctx, m_session_key, &outlen, xor_nonce, 16);
		EVP_EncryptFinal_ex(ctx, m_session_key + outlen, &outlen);
		EVP_CIPHER_CTX_free(ctx);
	}
	catch (const std::exception& e)
	{
		m_sessionState = Tuya::Session::INVALID;
		return false;
	}

#ifdef DEBUG
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
		m_sessionState = Tuya::Session::INVALID;
		return false;
	}

	// Try to receive any response (might be empty/ack)
	// std::this_thread::sleep_for(std::chrono::milliseconds(100));

#ifdef DEBUG
	std::cout << "dbg: Session negotiation complete\n";
#endif

	m_sessionState = Tuya::Session::ESTABLISHED;
	return true;
}


// deprecated - only works when blocking mode communication is enabled
bool tuyaAPI34::NegotiateSession(const std::string &szEncryptionKey)
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
	for(int i = 0; i < recvSize; ++i)
		printf("%.2x", (uint8_t)cMessageBuffer[i]);
	std::cout << "\n";
#endif
	return result;
}

#endif // WITHOUT_API34

