/*
 *  Async monitor example using tuyaAsync class
 *
 *  Copyright 2022 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#define DEBUG

#ifndef SECRETSFILE
#define SECRETSFILE "tuya-devices.json"
#endif

#include "tuyaAsync.hpp"
#include <iostream>
#include <json/json.h>
#include <fstream>
#include <sys/select.h>
#include <vector>

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
	std::cout.setf(std::ios::unitbuf);  // Unbuffered output

	if (argc < 2) {
		fprintf(stderr,"usage %s hostname [hostname2 ...]\n", argv[0]);
		exit(0);
	}

	std::vector<tuyaAsync*> devices;

	// Load all devices
	for (int i = 1; i < argc; i++) {
		std::string device_id, device_key, device_address, device_version;
		if (!get_device_by_name(std::string(argv[i]), device_id, device_key, device_address, device_version))
		{
			std::cout << "Error: Device " << argv[i] << " unknown\n";
			continue;
		}

#ifdef DEBUG
		std::cout << "Device " << argv[i] << ":\n";
		std::cout << "  id: " << device_id << "\n";
		std::cout << "  key: " << device_key << "\n";
		std::cout << "  address: " << device_address << "\n";
		std::cout << "  version: " << device_version << "\n";
#endif

		std::cout << "Monitoring device: " << argv[i] << " (" << device_address << ")\n";
		devices.push_back(new tuyaAsync(device_version, device_id, device_key, device_address));
	}

	if (devices.empty()) {
		std::cerr << "No valid devices to monitor\n";
		return 1;
	}

	while (true)
	{
		struct timeval tv = {0, 0};
		fd_set read_fds, write_fds;
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		int max_fd = -1;

		// Let each device run and collect their fd requirements
		for (auto dev : devices) {
			struct timeval dev_tv = {0, 0};
			dev->loop(dev_tv);

			// Use the minimum timeout
			if (tv.tv_sec == 0 || (dev_tv.tv_sec > 0 && dev_tv.tv_sec < tv.tv_sec))
				tv = dev_tv;

			int fd = dev->get_fd();
			if (fd >= 0) {
				if (dev->wants_write())
					FD_SET(fd, &write_fds);
				if (dev->wants_read())
					FD_SET(fd, &read_fds);
				if (fd > max_fd)
					max_fd = fd;
			}
		}

		if (max_fd >= 0)
			select(max_fd + 1, &read_fds, &write_fds, nullptr, &tv);
	}

	for (auto dev : devices)
		delete dev;

	return 0;
}
