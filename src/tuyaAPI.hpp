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

// Tuya API Base Class

#ifndef _tuyaAPI
#define _tuyaAPI

// Tuya Local Access TCP Port
#define TUYA_COMMAND_PORT 6668

// Tuya Command Types
#define TUYA_UDP 0  // HEART_BEAT_CMD
#define TUYA_AP_CONFIG 1  // PRODUCT_INFO_CMD
#define TUYA_ACTIVE 2  // WORK_MODE_CMD
#define TUYA_BIND 3  // WIFI_STATE_CMD - wifi working status
#define TUYA_RENAME_GW 4  // WIFI_RESET_CMD - reset wifi
#define TUYA_RENAME_DEVICE 5  // WIFI_MODE_CMD - Choose smartconfig/AP mode
#define TUYA_UNBIND 6  // DATA_QUERT_CMD - issue command
#define TUYA_CONTROL 7  // STATE_UPLOAD_CMD
#define TUYA_STATUS 8  // STATE_QUERY_CMD
#define TUYA_HEART_BEAT 9
#define TUYA_DP_QUERY 10  // UPDATE_START_CMD - get data points
#define TUYA_QUERY_WIFI 11  // UPDATE_TRANS_CMD
#define TUYA_TOKEN_BIND 12  // GET_ONLINE_TIME_CMD - system time (GMT)
#define TUYA_CONTROL_NEW 13  // FACTORY_MODE_CMD
#define TUYA_ENABLE_WIFI 14  // WIFI_TEST_CMD
#define TUYA_DP_QUERY_NEW 16
#define TUYA_SCENE_EXECUTE 17
#define TUYA_UPDATEDPS 18  // Request refresh of DPS
#define TUYA_UDP_NEW 19
#define TUYA_AP_CONFIG_NEW 20
#define TUYA_GET_LOCAL_TIME_CMD 28
#define TUYA_WEATHER_OPEN_CMD 32
#define TUYA_WEATHER_DATA_CMD 33
#define TUYA_STATE_UPLOAD_SYN_CMD 34
#define TUYA_STATE_UPLOAD_SYN_RECV_CMD 35
#define TUYA_HEART_BEAT_STOP 37
#define TUYA_STREAM_TRANS_CMD 38
#define TUYA_GET_WIFI_STATUS_CMD 43
#define TUYA_WIFI_CONNECT_TEST_CMD 44
#define TUYA_GET_MAC_CMD 45
#define TUYA_GET_IR_STATUS_CMD 46
#define TUYA_IR_TX_RX_TEST_CMD 47
#define TUYA_LAN_GW_ACTIVE 240
#define TUYA_LAN_SUB_DEV_REQUEST 241
#define TUYA_LAN_DELETE_SUB_DEV 242
#define TUYA_LAN_REPORT_SUB_DEV 243
#define TUYA_LAN_SCENE 244
#define TUYA_LAN_PUBLISH_CLOUD_CONFIG 245
#define TUYA_LAN_PUBLISH_APP_CONFIG 246
#define TUYA_LAN_EXPORT_APP_CONFIG 247
#define TUYA_LAN_PUBLISH_SCENE_PANEL 248
#define TUYA_LAN_REMOVE_GW 249
#define TUYA_LAN_CHECK_GW_UPDATE 250
#define TUYA_LAN_GW_UPDATE 251
#define TUYA_LAN_SET_GW_CHANNEL 252


#include "tuyaTCP.hpp"
#include <string>
#include <cstdint>


class tuyaAPI : public tuyaTCP
{
public:
	enum class Protocol {
		v31,
		v33,
		v34,
		v35
	};

	virtual ~tuyaAPI() {}

	static tuyaAPI* create(const std::string &version);

	// Get protocol version
	Protocol getProtocol() const { return m_protocol; }

	virtual void SetEncryptionKey(const std::string &key) { m_device_key = key; }
	bool NegotiateSession(const std::string &local_key);
	bool isSessionEstablished() const { return m_session_established; }

	std::string GeneratePayload(uint8_t &command, const std::string &szDeviceID, const std::string &szDatapoints);
	virtual int BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &payload, const std::string &encryption_key = "") = 0;
	virtual std::string DecodeTuyaMessage(unsigned char* buffer, const int size, const std::string &encryption_key = "") = 0;

	virtual int BuildSessionMessage(unsigned char *buffer) { m_session_established = true; return 0; }
	virtual std::string DecodeSessionMessage(unsigned char* buffer, const int size) { return ""; }

//	virtual unsigned long crc32(unsigned long crc, uint8_t const data[], uint32_t const len) { return 0;};

	// Crypto utility methods
	int aes_128_ecb_encrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output, int *output_len);
	int aes_128_ecb_decrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output, int *output_len);
	int aes_128_gcm_encrypt(const unsigned char *key, const unsigned char *iv, int iv_len,
	                        const unsigned char *aad, int aad_len,
	                        const unsigned char *input, int input_len,
	                        unsigned char *output, int *output_len,
	                        unsigned char *tag, int tag_len);
	int aes_128_gcm_decrypt(const unsigned char *key, const unsigned char *iv, int iv_len,
	                        const unsigned char *aad, int aad_len,
	                        const unsigned char *input, int input_len,
	                        const unsigned char *tag, int tag_len,
	                        unsigned char *output, int *output_len);
	void hmac_sha256(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *output);
	void md5_hash(const unsigned char *data, int data_len, unsigned char *output);
	void random_bytes(unsigned char *buffer, int len);

protected:
	Protocol m_protocol;
	std::string m_device_key;
	bool m_session_established;
};

#endif
