/*
 *  Status request example for local Tuya client
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
//#include <unistd.h>
#include <iostream>
#include <sstream>
#include <string.h>
#include <json/json.h>
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

#ifdef APPDEBUG
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
		std::cout << "Error connecting to device: " << strerror(tuyaclient->getlasterror()) << " (" << tuyaclient->getlasterror() << ")\n";
		exit(0);
	}

	if (!tuyaclient->NegotiateSession(device_key))
	{
		std::cout << "Error negotiating session\n";
		exit(1);
	}

	uint8_t command = TUYA_DP_QUERY;
	std::string payload = tuyaclient->GeneratePayload(command, device_id, "");
	int payload_len = tuyaclient->BuildTuyaMessage(message_buffer, command, payload);

	int numbytes;
	numbytes = tuyaclient->send(message_buffer, payload_len);
	numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1);
	if (numbytes < 0)
	{
		if (errno == 104)
			std::cout << "Command rejected: Device in use (" << tuyaclient->getlasterror() << ")\n";
		else
			std::cout << "Error reading from socket: " << strerror(tuyaclient->getlasterror()) << " (" << tuyaclient->getlasterror() << ")\n";
		exit(1);
	}

	std::string tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes);

#ifdef APPDEBUG
	std::cout << "dbg: raw answer: ";
	for(int i=0; i<numbytes; ++i)
		printf("%.2x", (uint8_t)message_buffer[i]);
	std::cout << "\n";
#endif

	std::cout << tuyaresponse << "\n";

	delete tuyaclient;

	return 0;
}
