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

#include "tuyaAPI.hpp"
#ifndef WITHOUT_API31
#include "tuyaAPI31.hpp"
#endif
#ifndef WITHOUT_API33
#include "tuyaAPI33.hpp"
#endif
#ifndef WITHOUT_API34
#include "tuyaAPI34.hpp"
#endif

#include <cstring>
#include <ctime>



namespace Tuya {
  namespace Commands {
    static const std::string HEART_BEAT = "{\"gwId\":\"@devid@\",\"devId\":\"@devid@\"}";
    static const std::string DP_QUERY = "{\"gwId\":\"@devid@\",\"devId\":\"@devid@\",\"uid\":\"@devid@\",\"t\":\"@now@\"}";
    static const std::string CONTROL = "{\"devId\":\"@devid@\",\"uid\":\"@devid@\",\"dps\":@dps@,\"t\":\"@now@\"}";
    static const std::string DP_QUERY_NEW = "{\"devId\":\"@devid@\",\"uid\":\"@devid@\",\"t\":\"@now@\"}";
    static const std::string CONTROL_NEW = "{\"protocol\":5,\"t\":@now@,\"data\":{\"dps\":@dps@}}";
    static const std::string UPDATEDPS = "";
  }; // namespace Commands
}; // namespace Tuya


tuyaAPI* tuyaAPI::create(const std::string &version)
{
#ifndef WITHOUT_API31
	if (version == "3.1")
		return new tuyaAPI31();
#endif
#ifndef WITHOUT_API33
	if (version == "3.3")
		return new tuyaAPI33();
#endif
#ifndef WITHOUT_API34
	if (version == "3.4")
		return new tuyaAPI34();
#endif
	return nullptr;
}


std::string tuyaAPI::GeneratePayload(const uint8_t command, const std::string &szDeviceID, const std::string &szDatapoints)
{
	std::string szPayload;
	switch (command)
	{
		case TUYA_HEART_BEAT:
			szPayload = Tuya::Commands::HEART_BEAT;
			szPayload.replace(28, 7, szDeviceID);
			szPayload.replace(10, 7, szDeviceID);
			break;
		case TUYA_DP_QUERY:
			szPayload = Tuya::Commands::DP_QUERY;
			szPayload.replace(57, 5, std::to_string(time(NULL)));
			szPayload.replace(43, 7, szDeviceID);
			szPayload.replace(27, 7, szDeviceID);
			szPayload.replace(9, 7, szDeviceID);
			break;
		case TUYA_CONTROL:
			szPayload = Tuya::Commands::CONTROL;
			szPayload.replace(52, 5, std::to_string(time(NULL)));
			szPayload.replace(41, 5, szDatapoints);
			szPayload.replace(26, 7, szDeviceID);
			szPayload.replace(10, 7, szDeviceID);
			break;
		case TUYA_DP_QUERY_NEW:
			szPayload = Tuya::Commands::DP_QUERY_NEW;
			szPayload.replace(40, 5, std::to_string(time(NULL)));
			szPayload.replace(26, 7, szDeviceID);
			szPayload.replace(10, 7, szDeviceID);
			break;
		case TUYA_CONTROL_NEW:
			szPayload = Tuya::Commands::CONTROL_NEW;
			szPayload.replace(38, 5, szDatapoints);
			szPayload.replace(18, 5, std::to_string(time(NULL)));
			break;
		default:			
			break;
	}
	return szPayload;
}


bool tuyaAPI::ConnectToDevice(const std::string &hostname)
{
	// Use base class connection
	if (!tuyaTCP::ConnectToDevice(hostname))
		return false;

	// Protocol 3.4+ requires session negotiation
	m_sessionState = Tuya::Session::INVALID;
	m_seqno = 0;
	return true;
}


