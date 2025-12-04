/*
 *  Switch action example for local Tuya client
 *
 *  Copyright 2022 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

//#define APPDEBUG

#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE 1024
#endif

#ifndef SECRETSFILE
#define SECRETSFILE "tuya-devices.json"
#endif

#include "tuyaAPI.hpp"
#include <iostream>
#include <sstream>
#include <string.h>
#include <json/json.h>

#include <fstream>


void error(const char *msg)
{
	perror(msg);
	exit(1);
}


bool get_device_by_name(const std::string name, std::string &id, std::string &key, std::string &address, std::string &version)
{
	std::string szFileContent;
	std::ifstream myfile (SECRETSFILE);
	if ( myfile.is_open() )
	{
		std::string line;
		while ( getline (myfile,line) )
		{
			szFileContent.append(line);
			szFileContent.append("\n");
		}
		myfile.close();
	}

	Json::Value jDevices;
	Json::CharReaderBuilder jBuilder;
	std::unique_ptr<Json::CharReader> jReader(jBuilder.newCharReader());
	jReader->parse(szFileContent.c_str(), szFileContent.c_str() + szFileContent.size(), &jDevices, nullptr);

	std::string lowername = name;
	for (int i=0;i<(int)lowername.length();i++)
	{
		if (lowername[i] & 0x40)
			lowername[i] = lowername[i] | 0x20;
	}

	if (jDevices["devices"].isArray())
	{
		for (int i=0;i<(int)jDevices["devices"].size();i++)
		{
			if (jDevices["devices"][i]["name"].asString() == lowername)
			{
				id =  jDevices["devices"][i]["id"].asString();
				key = jDevices["devices"][i]["key"].asString();
				address = jDevices["devices"][i]["address"].asString();
				version = jDevices["devices"][i]["version"].asString();
				return true;
			}
		}
	}
	return false;
}




int main(int argc, char *argv[])
{

	if (argc < 3) {
	   fprintf(stderr,"usage %s hostname on|off|toggle [countdown]\n", argv[0]);
	   exit(0);
	}

	std::string device_id, device_key, device_address, device_version;
	if (!get_device_by_name(std::string(argv[1]), device_id, device_key, device_address, device_version))
	{
		std::cout << "unkown device\n";
		exit(0);
	}

#ifdef APPDEBUG
	std::cout << "id : " << device_id << "\n";
	std::cout << "key : " << device_key<< "\n";
	std::cout << "address : " << device_address << "\n";
	std::cout << "version : " << device_version << "\n";
#endif

	unsigned char message_buffer[MAX_BUFFER_SIZE];

	tuyaAPI *tuyaclient = tuyaAPI::create(device_version);
	if (!tuyaclient)
	{
		std::cout << "Error: Unsupported protocol version " << device_version << "\n";
		exit(0);
	}

	if (!tuyaclient->ConnectToDevice(device_address))
		error("ERROR connecting");

	std::string s_switchstate = std::string(argv[2]);
	int countdown = 0;
	if (argc > 3)
		countdown = atoi(argv[3]);

	std::stringstream ss_payload;
	long currenttime = time(NULL) ;
	ss_payload << "{\"gwId\":\"" << device_id << "\",\"devId\":\"" << device_id << "\",\"uid\":\"" << device_id << "\",\"t\":\"" << currenttime << "\"}";
	std::string payload = ss_payload.str();

	int payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_DP_QUERY, payload, device_key);


	int numbytes = tuyaclient->send(message_buffer, payload_len);
	if (numbytes < 0)
		error("ERROR writing to socket");

	numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1);
	if (numbytes < 0)
		error("ERROR reading from socket");

	std::string tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes, device_key);

#ifdef APPDEBUG
	std::cout << "dbg: raw answer: ";
	for(int i=0; i<numbytes; ++i)
		printf("%.2x", (uint8_t)message_buffer[i]);
	std::cout << "\n";
	std::cout << "dbg: decoded answer: " << tuyaresponse << "\n";
#endif

	bool switchstate;
	if (s_switchstate == "on")
		switchstate = true;
	else if (s_switchstate == "off")
		switchstate = false;
	else if (s_switchstate == "toggle")
	{
		size_t pos = tuyaresponse.find("\"1\":");
		if (pos != std::string::npos)
		{
			if (tuyaresponse[(int)(pos+4)] == 't')
				switchstate = false;
			else
				switchstate = true;
		}
		else
			error("ERROR fetching current switch state");
	}

	ss_payload.str(std::string());

	// Protocol 3.4 uses different payload format
	if (tuyaclient->getProtocol() == tuyaAPI::Protocol::v34)
	{
		ss_payload << "{\"protocol\":5,\"t\":" << currenttime << ",\"data\":{\"dps\":{\"1\":";
		if (switchstate)
			ss_payload << "true";
		else
			ss_payload << "false";
		if (countdown)
			ss_payload << ",\"9\":" << countdown;
		ss_payload <<  "}}}";
	}
	else
	{
		// Protocol 3.3 and earlier use devId/uid format
		ss_payload << "{\"devId\":\"" << device_id << "\",\"uid\":\"" << device_id << "\",\"dps\":{\"1\":";
		if (switchstate)
			ss_payload << "true";
		else
			ss_payload << "false";
		if (countdown)
			ss_payload << ",\"9\":" << countdown;
		ss_payload <<  "},\"t\":\"" << currenttime << "\"}";
	}
	payload = ss_payload.str();

#ifdef APPDEBUG
	std::cout << "building switch payload: " << payload << "\n";
#endif

	payload_len = tuyaclient->BuildTuyaMessage(message_buffer,
		(tuyaclient->getProtocol() == tuyaAPI::Protocol::v34) ? TUYA_CONTROL_NEW : TUYA_CONTROL,
		payload, device_key);

#ifdef APPDEBUG
		std::cout << "sending message: ";
		for(int i=0; i<numbytes; ++i)
			printf("%.2x", (uint8_t)message_buffer[i]);
		std::cout << "\n";
#endif

	numbytes = tuyaclient->send(message_buffer, payload_len);
	if (numbytes < 0)
		error("ERROR writing to socket");

	numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1);
	if (numbytes < 0)
		error("ERROR reading from socket");

	tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes, device_key);
#ifdef APPDEBUG
	std::cout << "dbg: raw encrypted answer: ";
	for(int i=0; i<numbytes; ++i)
		printf("%.2x", (uint8_t)message_buffer[i]);
	std::cout << "\n";
	std::cout << "dbg: raw decoded answer: ";
	for(int i=0; i<(int)tuyaresponse.length(); ++i)
		printf("%.2x", (uint8_t)tuyaresponse[i]);
	std::cout << "\n";
	std::cout << tuyaresponse << "\n";
#endif

	delete tuyaclient;

	if (countdown)
	{
		// we're expecting multiple objects
		size_t pos = 0;
		while (pos != std::string::npos)
		{
			pos = tuyaresponse.find("{\"devId\":", pos + 20);
			if (pos != std::string::npos)
				tuyaresponse.insert(pos, 1, ',');
		}
		tuyaresponse.insert(0, std::string("{\"answers\":["));
		tuyaresponse.insert(tuyaresponse.length(), std::string("]}"));
	}

	Json::Value jResponse;
	Json::CharReaderBuilder jBuilder;
	std::unique_ptr<Json::CharReader> jReader(jBuilder.newCharReader());
	jReader->parse(tuyaresponse.c_str(), tuyaresponse.c_str() + tuyaresponse.size(), &jResponse, nullptr);
	
	bool newswitchstate;
	int newcountdown;
	time_t devtime;
	if (jResponse.isMember("answers"))
	{
		for (int i=0; i<(int)jResponse["answers"].size(); i++)
		{
			if (jResponse["answers"][i].isMember("dps"))
			{
				if (jResponse["answers"][i]["dps"].isMember("1"))
					newswitchstate = jResponse["answers"][i]["dps"]["1"].asBool();
				if (jResponse["answers"][i]["dps"].isMember("9"))
					newcountdown = jResponse["answers"][i]["dps"]["9"].asInt();
				devtime = jResponse["answers"][i]["t"].asUInt64();
			}
		}
		std::cout << "switch state: " << ((newswitchstate)?"on":"off");
		if (newcountdown)
		{
			devtime += newcountdown;
			struct tm ltime;
			if (localtime_r(&devtime, &ltime) != nullptr)
			{
				std::cout << " until " ;
				printf("%2d:%2d:%2d", ltime.tm_hour, ltime.tm_min, ltime.tm_sec);
			}
		}
		std::cout << "\n";
		
		if (newswitchstate == switchstate)
			return 0;
	}

	// switch command failed
	return 1;
}
