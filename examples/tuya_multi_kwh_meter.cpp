/*
 *  Threaded monitor example for local Tuya client
 *
 *  This example enables async communication in the base TCP class, showcasing
 *  how you can create a programmatically interruptable loop of requesting and
 *  reading/handling data.
 *
 *
 *  Copyright 2022-2026 - gordonb3 https://github.com/gordonb3/tuyapp
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

#define ENERGY_DIVISOR 10

#include "tuyaAPI.hpp"
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <json/json.h>
#include <cmath>

#include <fstream>
#include <chrono>
#include <thread>
#include <mutex>

#ifdef APPDEBUG
#include <iostream>
#endif


bool StopRequested = false;

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


int ReadFromDevice(tuyaAPI *tuyaclient, unsigned char *cMessageBuffer, const int timeout)
{
	int numbytes = -1;
	int i = 0;
	while ((numbytes <= 28) && (i < (timeout * 100)) && (!StopRequested))
	{
		i++;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		numbytes = tuyaclient->receive(cMessageBuffer, MAX_BUFFER_SIZE - 1);
		if (numbytes < 0)
		{
			// expect a timeout because the device will only respond to UPDATEDPS when the requested values change
#ifdef WIN32
			if (WSAGetLastError() == WSAEWOULDBLOCK)
				continue;
#else
			if ((errno == EAGAIN) || (errno == EINPROGRESS))
				continue;
#endif
			return numbytes;
		}

		if (numbytes <= 28)
		{
			// device sent us a message with an empty payload - wait for one that does contain an actual payload
			continue;
		}
	}
	return numbytes;
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

	tuyaclient->setAsyncMode();

	int i = 0;
	tuyaclient->ConnectToDevice(device_address);
	while (!tuyaclient->isConnected() && (i < 500) && (!StopRequested))
	{
#ifdef WIN32
		if (tuyaclient->getlasterror() != WSAEWOULDBLOCK)
			break;
#else
		if ((tuyaclient->getlasterror() != EAGAIN) && (tuyaclient->getlasterror() != EINPROGRESS))
			break;
#endif
		i++;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}

	if (tuyaclient->getlasterror() != 0)
	{
		writeprotect.lock();
		std::cout << "Error connecting to device: " << strerror(tuyaclient->getlasterror()) << " (" << tuyaclient->getlasterror() << ")\n";
		writeprotect.unlock();
		return false;
	}

	if (!tuyaclient->NegotiateSession(device_key))
	{
		std::cout << "Error negotiating session\n";
		writeprotect.unlock();
		return false;
	}

	uint8_t command = TUYA_DP_QUERY;
	std::string szPayload = tuyaclient->GeneratePayload(command, device_id, "");
	int payload_len = tuyaclient->BuildTuyaMessage(message_buffer, command, szPayload);

	int numbytes;
	numbytes = tuyaclient->send(message_buffer, payload_len);
	numbytes = ReadFromDevice(tuyaclient, message_buffer, 2);
	if (numbytes < 0)
	{
		writeprotect.lock();
		if (errno == 104)
			std::cout << "Command rejected: Device in use (" << tuyaclient->getlasterror() << ")\n";
		else
			std::cout << "Error reading from socket: " << strerror(tuyaclient->getlasterror()) << " (" << tuyaclient->getlasterror() << ")\n";
		writeprotect.unlock();
		return false;
	}

	std::string tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes);

	unsigned long timeval;
	float usage = 0;

	Json::Value jStatus;
	Json::CharReaderBuilder jBuilder;
	std::unique_ptr<Json::CharReader> jReader(jBuilder.newCharReader());
	jReader->parse(tuyaresponse.c_str(), tuyaresponse.c_str() + tuyaresponse.size(), &jStatus, nullptr);
	timeval = jStatus["t"].asUInt64();
	bool switchstate = jStatus["dps"]["1"].asBool();

	tuyaresponse.insert(1,"\"name\":\"\",");
	tuyaresponse.insert(9,devicename);
	std::cout << tuyaresponse << "\n";

	while (!StopRequested)
	{
		if (numbytes > 0)
		{
#ifdef APPDEBUG
			std::cout << "Sending new request for updates\n";
#endif			// send heart beat to keep connection alive
			// received data => make new request for data point updates for switch state, power and voltage
			szPayload = "{\"dpId\":[1,19,20]}";
			payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_UPDATEDPS, szPayload);
		}
		else
		{
#ifdef APPDEBUG
			std::cout << "Sending heart beat\n";
#endif			// send heart beat to keep connection alive
			uint8_t hb_command = TUYA_HEART_BEAT;
			szPayload = tuyaclient->GeneratePayload(hb_command, device_id, "");
			payload_len = tuyaclient->BuildTuyaMessage(message_buffer, hb_command, szPayload);
		}

		numbytes = tuyaclient->send(message_buffer, payload_len);
		numbytes = ReadFromDevice(tuyaclient, message_buffer, 10);
		if (numbytes > 0)
		{
			tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes);

			jReader->parse(tuyaresponse.c_str(), tuyaresponse.c_str() + tuyaresponse.size(), &jStatus, nullptr);
			if (jStatus["dps"].isMember("1"))
			{
				bool newswitchstate = jStatus["dps"]["1"].asBool();
				if (newswitchstate != switchstate)
				{
					std::string sstate = newswitchstate?"on":"off";
					writeprotect.lock();
					std::cout << "{\"name\":\"" << devicename << ",\"switch\":" << sstate <<  "}\n";
					writeprotect.unlock();
					switchstate = newswitchstate;
				}
			}
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
				if (jStatus["dps"].isMember("19"))
				{
					unsigned int timediff = (int)(newtimeval - timeval);
					unsigned int actual = jStatus["dps"]["19"].asUInt();
					usage += (float)(actual * timediff) / (3600.0 * ENERGY_DIVISOR);
					writeprotect.lock();
					std::cout << "{\"name\":\"" << devicename;
					std::cout << "\",\"power\":" << (float)(actual + 0.0)/ENERGY_DIVISOR << ",\"usage\":" <<  (int)std::round(usage)<< ",\"rawusage\":" << usage;
					std::cout << voltreport.str() << ",\"t1\":" <<  timeval <<  ",\"t2\":" << newtimeval  <<  "}\n";
					writeprotect.unlock();
					timeval = newtimeval;
				}
				else if (jStatus["dps"].isMember("20"))
				{
					writeprotect.lock();
					std::cout << "{\"name\":\"" << devicename;
					std::cout << voltreport.str() <<  "}\n";
					writeprotect.unlock();
				}
			}
			else
				timeval = newtimeval;
		}
		else
		{
#ifdef WIN32
			if (WSAGetLastError() == WSAEWOULDBLOCK)
				continue;
#else
			if ((errno == EAGAIN) || (errno == EINPROGRESS))
				continue;
#endif
			writeprotect.lock();
			std::cout << "Error reading from socket: " << strerror(errno) << " (" << errno << ")\n";
			writeprotect.unlock();
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

	std::cout << "Press Enter to quit\n";
	char c;
	std::cin.get(c);
	StopRequested = true;

	for (auto &t1 : monitorthreads)
	{
		t1->join();
	}

}

