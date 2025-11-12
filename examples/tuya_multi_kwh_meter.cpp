/*
 *  Threaded monitor example for local Tuya client
 *
 *  Copyright 2022 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

//#define DEBUG

#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE 1024
#endif

#ifndef SECRETSFILE
#define SECRETSFILE "tuya-devices.json"
#endif

#define ENERGY_DIVISOR 10

#include "tuyaAPI.hpp"
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <string.h>
#include <json/json.h>
#include <cmath>

#include <fstream>
#include <thread>
#include <mutex>


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


bool monitor(std::string devicename)
{
	std::mutex writeprotect;
	std::string device_id, device_key, device_address, device_version;
	if (!get_device_by_name(devicename, device_id, device_key, device_address, device_version))
	{
		writeprotect.lock();
		std::cout << "Error: Device unknown\n";
		writeprotect.unlock();
		return true;
	}

	unsigned char message_buffer[MAX_BUFFER_SIZE];

	tuyaAPI *tuyaclient = tuyaAPI::create(device_version);
	if (!tuyaclient)
	{
		std::cout << "Error: Unsupported protocol version " << device_version << "\n";
		exit(0);
	}

	if (!tuyaclient->ConnectToDevice(device_address, TUYA_COMMAND_PORT))
	{
		writeprotect.lock();
		std::cout << "Error connecting to device: " << strerror(errno) << " (" << errno << ")\n";
		writeprotect.unlock();
		return false;
	}

	std::stringstream ss_payload;
	long currenttime = time(NULL) ;
	ss_payload << "{\"gwId\":\"" << device_id << "\",\"devId\":\"" << device_id << "\",\"uid\":\"" << device_id << "\",\"t\":\"" << currenttime << "\"}";
	std::string payload = ss_payload.str();

	int payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_DP_QUERY, payload, device_key);


	int numbytes = tuyaclient->send(message_buffer, payload_len);
	if (numbytes < 0)
	{
		writeprotect.lock();
		std::cout << "Error writing to socket: " << strerror(errno) << " (" << errno << ")\n";
		writeprotect.unlock();
		return false;
	}

	numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1);
	if (numbytes < 0)
	{
		writeprotect.lock();
		if (errno == 104)
			std::cout << "Command rejected: Device in use (" << errno << ")\n";
		else
			std::cout << "Error reading from socket: " << strerror(errno) << " (" << errno << ")\n";
		writeprotect.unlock();
		return false;
	}

	std::string tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes, device_key);

	unsigned long timeval;
	float usage = 0;

	Json::Value jStatus;
	Json::CharReaderBuilder jBuilder;
	std::unique_ptr<Json::CharReader> jReader(jBuilder.newCharReader());
	jReader->parse(tuyaresponse.c_str(), tuyaresponse.c_str() + tuyaresponse.size(), &jStatus, nullptr);
	timeval = jStatus["t"].asUInt64();

	while(true)
	{
		payload = "{\"dpId\":[19,20]}";
		payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_UPDATEDPS, payload, device_key);
		numbytes = tuyaclient->send(message_buffer, payload_len);
		if (numbytes < 0)
			if (numbytes < 0)
			{
				writeprotect.lock();
				std::cout << "Error writing to socket: " << strerror(errno) << " (" << errno << ")\n";
				writeprotect.unlock();
				return false;
			}

		numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1);
		if (numbytes < 0)
		{
			// expect a timeout because the device will only send updates when the requested values change
			if (errno != 11)
			{
				writeprotect.lock();
				std::cout << "Error reading from socket: " << strerror(errno) << " (" << errno << ")\n";
				writeprotect.unlock();
				return false;
			}
		}
		else
		{
			tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes, device_key);

			jReader->parse(tuyaresponse.c_str(), tuyaresponse.c_str() + tuyaresponse.size(), &jStatus, nullptr);
			unsigned long newtimeval = jStatus["t"].asUInt64();
			if (timeval)
			{
				std::stringstream voltreport("");
				if (jStatus["dps"].isMember("20"))
				{
					unsigned int decivolts = jStatus["dps"]["20"].asUInt();
					float volts = (float)(decivolts)/10;
					voltreport << ",\"volts\":" << volts;
				}
				writeprotect.lock();
				std::cout << "{\"name\":\"" << devicename;
				if (jStatus["dps"].isMember("19"))
				{
					unsigned int timediff = (int)(newtimeval - timeval);
					unsigned int actual = jStatus["dps"]["19"].asUInt();
					usage += (float)(actual * timediff) / (3600.0 * ENERGY_DIVISOR);
					std::cout << "\",\"power\":" << (float)(actual + 0.0)/ENERGY_DIVISOR << ",\"usage\":" <<  (int)std::round(usage)<< ",\"rawusage\":" << voltreport.str() << ",\"t1\":" <<  timeval <<  ",\"t2\":" << newtimeval  <<  "}\n";
					timeval = newtimeval;
				}
				else
					std::cout << voltreport.str() <<  "}\n";
				writeprotect.unlock();
			}
			else
				timeval = newtimeval;
		}
	}

	delete tuyaclient;

	return 0;
}



int main(int argc, char *argv[])
{
	if (argc < 2) {
	   fprintf(stderr,"usage %s hostname [hostname] ...\n", argv[0]);
	   exit(0);
	}

	std::vector<std::thread*> monitorthreads;
	for (int i = 1; i < argc; i++)
	{
		std::thread* t1 = new std::thread(monitor, std::string(argv[i]));
		monitorthreads.push_back(t1);
	}

	for (auto &t1 : monitorthreads)
	{
		t1->join();
	}

}

