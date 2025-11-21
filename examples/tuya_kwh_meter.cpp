/*
 *  Power usage monitor example for local Tuya client
 *
 *  Copyright 2022 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */


#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE 1024
#endif

#ifndef SECRETSFILE
#define SECRETSFILE "tuya-devices.json"
#endif

#include "tuyaAPI.hpp"
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <string.h>
#include <json/json.h>
#include <cmath>
#include <chrono>
#include <thread>



#include <fstream>


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
	if (argc < 2) {
	   fprintf(stderr,"usage %s hostname\n", argv[0]);
	   exit(0);
	}

	std::string device_id, device_key, device_address, device_version;
	if (!get_device_by_name(std::string(argv[1]), device_id, device_key, device_address, device_version))
	{
		std::cout << "Error: Device unknown\n";
		exit(0);
	}

#ifdef DEBUG
	std::cout << "dbg: Device details:\n";
	std::cout << "  id : " << device_id << "\n";
	std::cout << "  key : " << device_key<< "\n";
	std::cout << "  address : " << device_address << "\n";
	std::cout << "  version : " << device_version << "\n";
#endif

	unsigned char message_buffer[MAX_BUFFER_SIZE];

	tuyaAPI *tuyaclient = tuyaAPI::create(device_version);
	if (!tuyaclient)
	{
		std::cout << "Error: Unsupported protocol version " << device_version << "\n";
		exit(0);
	}

	if (!tuyaclient->ConnectToDevice(device_address))
	{
		std::cout << "Error connecting to device: " << strerror(errno) << " (" << errno << ")\n";
		exit(1);
	}

	std::stringstream ss_payload;
	long currenttime = time(NULL) ;
	ss_payload << "{\"gwId\":\"" << device_id << "\",\"devId\":\"" << device_id << "\",\"uid\":\"" << device_id << "\",\"t\":\"" << currenttime << "\"}";
	std::string payload = ss_payload.str();

	int payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_DP_QUERY, payload, device_key);


	int numbytes = tuyaclient->send(message_buffer, payload_len);
	if (numbytes < 0)
	{
		std::cout << "Error writing to socket: " << strerror(errno) << " (" << errno << ")\n";
		exit(0);
	}

	numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1);
	if (numbytes < 0)
	{
		if (errno == 104)
			std::cout << "Command rejected: Device in use (" << errno << ")\n";
		else
			std::cout << "Error reading from socket: " << strerror(errno) << " (" << errno << ")\n";
		exit(1);
	}

	std::string tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes, device_key);


#ifdef DEBUG
	std::cout << "dbg: raw answer: ";
	for(int i=0; i<numbytes; ++i)
		printf("%.2x", (uint8_t)message_buffer[i]);
	std::cout << "\n";
	std::cout << "dbg: decoded answer: " << tuyaresponse << "\n";
#endif

	unsigned long timeval;
	float usage = 0;

	Json::Value jStatus;
	Json::CharReaderBuilder jBuilder;
	std::unique_ptr<Json::CharReader> jReader(jBuilder.newCharReader());
	jReader->parse(tuyaresponse.c_str(), tuyaresponse.c_str() + tuyaresponse.size(), &jStatus, nullptr);
	timeval = jStatus["t"].asUInt64();
	bool switchstate = jStatus["dps"]["1"].asBool();

	while(true)
	{
		if (numbytes > 0)
		{
			// received data => make new request for data point updates for switch state, power and voltage
			payload = "{\"dpId\":[1,19]}";
			payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_UPDATEDPS, payload, device_key);
		}
		else
		{
			// send heart beat to keep connection alive
			payload = "{\"gwId\":\"" + device_id + "\",\"devId\":\"" + device_id + "\"}";
			payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_HEART_BEAT, payload, device_key);
		}

		numbytes = tuyaclient->send(message_buffer, payload_len);
		if (numbytes < 0)
		{
			if (errno == EAGAIN)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				int so_error = tuyaclient->getlasterror();
				if ( so_error != 0)
				{
					std::cout << "Error writing to socket: " << so_error << "\n";
					exit(1);
				}
				std::cout << "last socket state: " << so_error << "(" << errno << "(\n";
			}
			else
			{
				std::cout << "Error writing to socket: " << strerror(errno) << " (" << errno << ")\n";
				exit(1);
			}
		}

		numbytes = -1;
		int i = 0;
		while ((numbytes <= 28) && (i < 1000))  // 10 seconds
		{
			i++;
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1, 0, false);
			if (numbytes < 0)
			{
				// expect a timeout because the device will only send updates when the requested values change
				if (errno == EAGAIN)
					continue;
				std::cout << "Error reading from socket: " << strerror(errno) << " (" << errno << ") (i = " << i << ")\n";
				exit(1);
			}

			if (numbytes <= 28)
			{
				// device sent us a message with an empty payload - wait for one that does contain an actual payload
				continue;
			}
		}

#ifdef DEBUG
		if (numbytes < 0)
			std::cout << "{\"msg\":\"timeout reached\",\"code\":" << errno << "}\n";
#endif

		if (numbytes > 0)
		{
			tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes, device_key);
#ifdef DEBUG
			std::cout << "dbg: raw answer: ";
			for(int i=0; i<numbytes; ++i)
				printf("%.2x", (uint8_t)message_buffer[i]);
			std::cout << "\n";
			std::cout << "dbg: decoded answer: " << tuyaresponse << "\n";
#endif

			jReader->parse(tuyaresponse.c_str(), tuyaresponse.c_str() + tuyaresponse.size(), &jStatus, nullptr);
			if (jStatus["dps"].isMember("1"))
			{
				bool newswitchstate = jStatus["dps"]["1"].asBool();
				if (newswitchstate != switchstate)
				{
					std::string sstate = newswitchstate?"on":"off";
					std::cout << "{\"switch\":" << sstate <<  "}\n";
					switchstate = newswitchstate;
				}
			}
			unsigned long newtimeval = jStatus["t"].asUInt64();
			if (timeval)
			{
				unsigned int timediff = (int)(newtimeval - timeval);
				unsigned int actual = jStatus["dps"]["19"].asUInt();
				usage += (float)(actual * timediff / 36000.0);
				std::cout << "{\"power\":" << (actual + 0.0)/10 << ",\"usage\":" <<  (int)std::round(usage)<< ",\"rawusage\":" <<  usage <<  ",\"t1\":" <<  timeval <<  ",\"t2\":" << newtimeval  <<  "}\n";
			}
			timeval = newtimeval;
		}
	}

	delete tuyaclient;

	return 0;
}
