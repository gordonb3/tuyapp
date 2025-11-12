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
#include <zlib.h>
#include <cstring>
#include <thread>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>


tuyaAPI34::tuyaAPI34()
{
	m_session_established = false;
	m_seqno = 0;
}


int tuyaAPI34::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload, const std::string &encryption_key)
{
	if (!m_session_established)
	{
		if (!NegotiateSession(encryption_key))
			return -1;
	}

	m_seqno++;

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

#ifdef DEBUG
	std::cout << "dbg: Payload to encrypt (" << szPayload.length() << " bytes): " << szPayload << "\n";
#endif

	unsigned char* cEncryptedPayload = &buffer[bufferpos];
	int payloadSize = (int)szPayload.length();
	memset(cEncryptedPayload, 0, payloadSize + 16);
	int encryptedSize = 0;
	int encryptedChars = 0;

	try
	{
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, m_session_key, nullptr);
		EVP_EncryptUpdate(ctx, cEncryptedPayload, &encryptedChars, (unsigned char*)szPayload.c_str(), payloadSize);
		encryptedSize = encryptedChars;
		EVP_EncryptFinal_ex(ctx, cEncryptedPayload + encryptedChars, &encryptedChars);
		encryptedSize += encryptedChars;
		EVP_CIPHER_CTX_free(ctx);
	}
	catch (const std::exception& e)
	{
		return -1;
	}

	bufferpos += encryptedSize;
	unsigned char* cMessageTrailer = &buffer[bufferpos];

	int buffersize = bufferpos + 36;  // 32 bytes HMAC + 4 bytes suffix
	buffer[14] = ((buffersize - PROTOCOL_34_HEADER_SIZE) & 0x0000FF00) >> 8;
	buffer[15] = (buffersize - PROTOCOL_34_HEADER_SIZE) & 0x000000FF;

	// Calculate HMAC-SHA256 of header + encrypted payload
	unsigned int hmac_len;
	HMAC(EVP_sha256(), m_session_key, 16, buffer, bufferpos, cMessageTrailer, &hmac_len);

	cMessageTrailer[32] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	cMessageTrailer[33] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	cMessageTrailer[34] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	cMessageTrailer[35] = (MESSAGE_SUFFIX & 0x000000FF);

#ifdef DEBUG
	std::cout << "dbg: normal message (size=" << buffersize << "): ";
	for(int i=0; i<buffersize; ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
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

		unsigned int crc_sent = ((uint8_t)cTuyaResponse[messageSize - 8] << 24) + ((uint8_t)cTuyaResponse[messageSize - 7] << 16) + ((uint8_t)cTuyaResponse[messageSize - 6] << 8) + (uint8_t)cTuyaResponse[messageSize - 5];
		unsigned int crc = crc32(0L, Z_NULL, 0) & 0xFFFFFFFF;
		crc = crc32(crc, cTuyaResponse, messageSize - 8) & 0xFFFFFFFF;

		// For v3.4, verify HMAC instead of CRC
		unsigned char hmac_sent[32];
		memcpy(hmac_sent, &cTuyaResponse[messageSize - 36], 32);

		unsigned char hmac_calc[32];
		unsigned int hmac_len;
		HMAC(EVP_sha256(), m_session_key, 16, cTuyaResponse, messageSize - 36, hmac_calc, &hmac_len);

		if (memcmp(hmac_sent, hmac_calc, 32) == 0)
		{
			unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_34_HEADER_SIZE + sizeof(retcode)];
			int payloadSize = (int)(messageSize - PROTOCOL_34_HEADER_SIZE - sizeof(retcode) - 36);  // 36 = 32 HMAC + 4 suffix

			unsigned char* cDecryptedPayload = new unsigned char[payloadSize + 16];
			memset(cDecryptedPayload, 0, payloadSize + 16);
			int decryptedSize = 0;
			int decryptedChars = 0;

			try
			{
				EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
				EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, m_session_key, nullptr);
				EVP_DecryptUpdate(ctx, cDecryptedPayload, &decryptedChars, cEncryptedPayload, payloadSize);
				decryptedSize = decryptedChars;
				EVP_DecryptFinal_ex(ctx, cDecryptedPayload + decryptedSize, &decryptedChars);
				decryptedSize += decryptedChars;
				EVP_CIPHER_CTX_free(ctx);

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
			catch (const std::exception& e)
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


/* private */ int tuyaAPI34::BuildSessionMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload, const std::string &encryption_key)
{
	static uint32_t session_seqno = 1;

	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_34_HEADER_SIZE);
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	buffer[4] = (session_seqno & 0xFF000000) >> 24;
	buffer[5] = (session_seqno & 0x00FF0000) >> 16;
	buffer[6] = (session_seqno & 0x0000FF00) >> 8;
	buffer[7] = (session_seqno & 0x000000FF);
	buffer[11] = command;
	bufferpos += (int)PROTOCOL_34_HEADER_SIZE;

	session_seqno++;  // Increment by 1 for next message

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
		return -1;
	}

	bufferpos += encryptedSize;
	unsigned char* cMessageTrailer = &buffer[bufferpos];

	int buffersize = bufferpos + MESSAGE_TRAILER_SIZE;
	buffer[14] = ((buffersize - PROTOCOL_34_HEADER_SIZE) & 0x0000FF00) >> 8;
	buffer[15] = (buffersize - PROTOCOL_34_HEADER_SIZE) & 0x000000FF;

	// Calculate HMAC-SHA256
	unsigned int hmac_len;
	HMAC(EVP_sha256(), (unsigned char*)encryption_key.c_str(), encryption_key.length(),
	     buffer, bufferpos, cMessageTrailer, &hmac_len);

	cMessageTrailer[32] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	cMessageTrailer[33] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	cMessageTrailer[34] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	cMessageTrailer[35] = (MESSAGE_SUFFIX & 0x000000FF);

#ifdef DEBUG
	std::cout << "dbg: session message (size=" << buffersize << "): ";
	for(int i=0; i<buffersize; ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}


/* private */ std::string tuyaAPI34::DecodeSessionMessage(unsigned char* buffer, const int size, const std::string &encryption_key)
{
	std::string result;
	unsigned char* cTuyaResponse = buffer;
	int messageSize = (int)((uint8_t)cTuyaResponse[15] + ((uint8_t)cTuyaResponse[14] << 8) + PROTOCOL_34_HEADER_SIZE);

	// Session messages have a 4-byte retcode after the header
	unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_34_HEADER_SIZE + 4];
	int payloadSize = (int)(messageSize - PROTOCOL_34_HEADER_SIZE - 4 - MESSAGE_TRAILER_SIZE);

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
		result.append((char*)cDecryptedPayload, decryptedSize);
	}
	catch (const std::exception& e)
	{
		result.append("{\"msg\":\"error decrypting payload\"}");
	}

	delete[] cDecryptedPayload;
	return result;
}


/* private */ bool tuyaAPI34::NegotiateSession(const std::string &local_key)
{
#ifdef DEBUG
	std::cout << "dbg: NegotiateSession called\n";
#endif
	unsigned char buffer[1024];

	RAND_bytes(m_local_nonce, 16);

#ifdef DEBUG
	std::cout << "dbg: Starting session negotiation\n";
#endif

	int msgSize = BuildSessionMessage(buffer, 3, std::string((char*)m_local_nonce, 16), local_key);
	if (msgSize < 0)
	{
#ifdef DEBUG
		std::cout << "dbg: Failed to build session message 1\n";
#endif
		return false;
	}

	if (send(buffer, msgSize) < 0)
	{
#ifdef DEBUG
		std::cout << "dbg: Failed to send session message 1\n";
#endif
		return false;
	}

#ifdef DEBUG
	std::cout << "dbg: Waiting for session response\n";
#endif

	int recvSize = receive(buffer, sizeof(buffer), 0);

#ifdef DEBUG
	std::cout << "dbg: receive() returned " << recvSize << "\n";
#endif

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

	std::string response = DecodeSessionMessage(buffer, recvSize, local_key);
	if (response.length() < 48)
	{
#ifdef DEBUG
		std::cout << "dbg: Response too short: " << response.length() << " bytes\n";
#endif
		return false;
	}

#ifdef DEBUG
	std::cout << "dbg: Decrypted response (" << response.length() << " bytes): ";
	for(size_t i=0; i<response.length() && i<48; ++i)
		printf("%.2x", (unsigned char)response[i]);
	std::cout << "\n";
#endif

	// Extract remote_nonce (first 16 bytes) - it's ASCII hex string, use it directly
	memcpy(m_remote_nonce, response.c_str(), 16);

	// Verify HMAC(local_key, local_nonce) matches bytes 16-47
	unsigned char hmac_check[32];
	unsigned int hmac_check_len;
	HMAC(EVP_sha256(), (unsigned char*)local_key.c_str(), local_key.length(),
	     m_local_nonce, 16, hmac_check, &hmac_check_len);

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

	// Encrypt XOR'd nonce with local_key using ECB to get session key
	try
	{
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		int outlen;
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)local_key.c_str(), nullptr);
		EVP_EncryptUpdate(ctx, m_session_key, &outlen, xor_nonce, 16);
		EVP_EncryptFinal_ex(ctx, m_session_key + outlen, &outlen);
		EVP_CIPHER_CTX_free(ctx);
	}
	catch (const std::exception& e)
	{
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
	unsigned int hmac_len;
	HMAC(EVP_sha256(), (unsigned char*)local_key.c_str(), local_key.length(),
	     m_remote_nonce, 16, rkey_hmac, &hmac_len);

	msgSize = BuildSessionMessage(buffer, 5, std::string((char*)rkey_hmac, 32), local_key);
	if (msgSize < 0 || send(buffer, msgSize) < 0)
	{
#ifdef DEBUG
		std::cout << "dbg: Failed to send session message 2\n";
#endif
		return false;
	}

	// Try to receive any response (might be empty/ack)
	std::this_thread::sleep_for(std::chrono::milliseconds(100));

#ifdef DEBUG
	std::cout << "dbg: Session negotiation complete\n";
#endif

	m_session_established = true;
	m_seqno = 2;  // Session used seqno 1 and 2, start data at 3
	return true;
}



