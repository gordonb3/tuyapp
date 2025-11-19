/*
 *  Monitor example for local Tuya client - async connection and updates
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
#include <iostream>
#include <sstream>
#include <string.h>
#include <json/json.h>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <time.h>

enum State {
	DISCONNECTED,
	CONNECTING,
	NEGOTIATING,
	CONNECTED,
	DISCONNECTING
};

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
	std::cout << "Device details:\n";
	std::cout << "  id: " << device_id << "\n";
	std::cout << "  key: " << device_key << "\n";
	std::cout << "  address: " << device_address << "\n";
	std::cout << "  version: " << device_version << "\n";
#endif

	std::cout << "Monitoring device: " << argv[1] << " (" << device_address << ")\n";
	std::cout.flush();

	tuyaAPI *tuyaclient = tuyaAPI::create(device_version);
	if (!tuyaclient)
	{
		std::cout << "Error: Unsupported protocol version " << device_version << "\n";
		exit(0);
	}

	State state = DISCONNECTED;
	int sockfd = -1;
	unsigned char message_buffer[MAX_BUFFER_SIZE];
	time_t last_rx_time = 0;
	time_t state_start_time = 0;
	time_t last_connect_attempt = 0;

	while (true)
	{
		struct timeval tv = {0, 0};
		time_t now = time(NULL);

		switch (state)
		{
		case DISCONNECTED:
			// Only attempt connect if enough time has passed since last attempt
			if (time(NULL) - last_connect_attempt < 10)
				break;

			std::cout << "Connecting to " << device_address << ":6668...\n";
			last_connect_attempt = time(NULL);

			// Reset API state for new connection
			delete tuyaclient;
			tuyaclient = tuyaAPI::create(device_version);
			if (!tuyaclient) {
				std::cerr << "Failed to create API\n";

				break;
			}

			sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (sockfd < 0) {
				std::cerr << "Failed to create socket\n";

				break;
			}

			fcntl(sockfd, F_SETFL, O_NONBLOCK);

			{
				struct sockaddr_in addr;
				addr.sin_family = AF_INET;
				addr.sin_port = htons(6668);
				inet_pton(AF_INET, device_address.c_str(), &addr.sin_addr);

				int err = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
				if (err != 0 && errno != EINPROGRESS) {
					std::cerr << "Connect failed: " << strerror(errno) << "\n";
					state = DISCONNECTING;
					continue;
				}
#ifdef DEBUG
				std::cout << "Connect initiated (EINPROGRESS)\n";
#endif
			}
			state = CONNECTING;
			state_start_time = time(NULL);
			break;

		case DISCONNECTING:
			close(sockfd);
			sockfd = -1;
			state = DISCONNECTED;
			break;

		case CONNECTING:
		{
			// Check for timeout
			if (time(NULL) - state_start_time > 5) {
				std::cerr << "Connection timeout\n";
				state = DISCONNECTING;
				continue;
			}

			// Check if socket is writable (connection complete)
			fd_set write_fds;
			FD_ZERO(&write_fds);
			FD_SET(sockfd, &write_fds);
			struct timeval tv = {0, 0};
			int ret = select(sockfd + 1, nullptr, &write_fds, nullptr, &tv);

			if (ret <= 0 || !FD_ISSET(sockfd, &write_fds))
				break;  // Not ready yet

			// Socket is writable - check if connection succeeded
			int error = 0;
			socklen_t len = sizeof(error);
			if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
				std::cerr << "Connection failed: " << strerror(error) << "\n";
				state = DISCONNECTING;
				continue;
			}

			std::cout << "Connected!\n";

			// Set encryption key now that we're connected
			tuyaclient->SetEncryptionKey(device_key);

			// Start negotiation
			unsigned char session_msg[MAX_BUFFER_SIZE];
			int session_len = tuyaclient->BuildSessionMessage(session_msg);
			if (session_len < 0) {
				std::cerr << "Failed to build session message\n";
				state = DISCONNECTING;
				continue;
			}

#ifdef DEBUG
			if (session_len > 0)
				std::cout << "Built session message: " << session_len << " bytes\n";
			else
				std::cout << "No negotiation needed\n";
#endif
			state = NEGOTIATING;
			state_start_time = time(NULL);
			last_rx_time = time(NULL);

			// Transitioned to NEGOTIATING - send first packet if we have one
			if (session_len > 0) {
				ssize_t sent = write(sockfd, session_msg, session_len);
				if (sent > 0) {
#ifdef DEBUG
					std::cout << "Sent negotiation packet: " << sent << " bytes\n";
#endif
				} else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
					std::cerr << "Write error: " << strerror(errno) << "\n";
					state = DISCONNECTING;
					continue;
				}
			}
			break;
		}

		case NEGOTIATING:
		{
			// Check for timeout
			if (time(NULL) - state_start_time > 5) {
				std::cerr << "Negotiation timeout\n";
				state = DISCONNECTING;
				continue;
			}

			// If not yet established, do negotiation work
			if (!tuyaclient->isSessionEstablished()) {
				// Read response
				ssize_t len = read(sockfd, message_buffer, sizeof(message_buffer));
				if (len > 0) {
#ifdef DEBUG
					std::cout << "Received negotiation response: " << len << " bytes\n";
#endif
					tuyaclient->DecodeSessionMessage(message_buffer, len);

					if (tuyaclient->isSessionEstablished()) {
						std::cout << "Negotiation complete\n";
						state = CONNECTED;
						last_rx_time = time(NULL);
					} else {
						unsigned char session_msg[MAX_BUFFER_SIZE];
						int session_len = tuyaclient->BuildSessionMessage(session_msg);
						if (session_len < 0) {
							std::cerr << "Negotiation failed\n";
							state = DISCONNECTING;
							continue;
						} else if (session_len > 0) {
							// Send immediately
							ssize_t sent = write(sockfd, session_msg, session_len);
							if (sent > 0) {
#ifdef DEBUG
								std::cout << "Sent negotiation packet: " << sent << " bytes\n";
#endif

								// Check if negotiation complete
								if (tuyaclient->isSessionEstablished()) {
									std::cout << "Negotiation complete\n";
									state = CONNECTED;
									last_rx_time = time(NULL);
								}
							} else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
								std::cerr << "Write error: " << strerror(errno) << "\n";
								state = DISCONNECTING;
								continue;
							}
						}
					}
				} else if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
					std::cerr << "Read error: " << strerror(errno) << "\n";
					state = DISCONNECTING;
					continue;
				}
			}

			// Transitioned to CONNECTED - send initial DP query
			uint8_t command = TUYA_DP_QUERY;
			std::string payload = tuyaclient->GeneratePayload(command, device_id, "");

			int len = tuyaclient->BuildTuyaMessage(message_buffer, command, payload);
			if (len > 0) {
				ssize_t sent = write(sockfd, message_buffer, len);
				if (sent == len) {
					std::cout << "Sent DP query\n";
					std::cout << "Monitoring for updates (Ctrl-C to exit)...\n";
				}
			}
			break;
		}

		case CONNECTED:
		{
			// Check for incoming data
			ssize_t len = read(sockfd, message_buffer, sizeof(message_buffer));
			if (len > 0) {
				last_rx_time = time(NULL);
				std::string decoded = tuyaclient->DecodeTuyaMessage(message_buffer, len);
				if (!decoded.empty()) {
					std::cout << "Received: " << decoded << "\n";
				}
			} else if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
				std::cerr << "Read error: " << strerror(errno) << "\n";
				state = DISCONNECTING;
				continue;
			} else if (len == 0) {
				std::cout << "Connection closed by device\n";
				state = DISCONNECTING;
				continue;
			}

			// Send heartbeat if no data for 5 seconds
			time_t now = time(NULL);
			if (now - last_rx_time > 5) {
				int len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_HEART_BEAT, "");
				if (len > 0) {
					ssize_t sent = write(sockfd, message_buffer, len);
					if (sent == len) {
						std::cout << "Sent heartbeat\n";
						last_rx_time = now;
					}
				}
			}
			break;
		}
		}

		// Calculate timeout based on state
		switch (state) {
		case DISCONNECTED:
			tv.tv_sec = 10 - (now - last_connect_attempt);  // 10s between reconnect attempts
			if (tv.tv_sec < 0) tv.tv_sec = 0;
			tv.tv_usec = 0;
			break;
		case CONNECTING:
			tv.tv_sec = 5 - (now - state_start_time);  // 5 second connect timeout
			if (tv.tv_sec < 0) tv.tv_sec = 0;
			tv.tv_usec = 0;
			break;
		case NEGOTIATING:
			tv.tv_sec = 5 - (now - state_start_time);  // 5 second negotiation timeout
			if (tv.tv_sec < 0) tv.tv_sec = 0;
			tv.tv_usec = 0;
			break;
		case CONNECTED:
			tv.tv_sec = 5 - (now - last_rx_time);  // Wake to send heartbeat
			if (tv.tv_sec < 0) tv.tv_sec = 0;
			tv.tv_usec = 0;
			break;
		case DISCONNECTING:
			tv.tv_sec = 0;  // Immediate
			tv.tv_usec = 0;
			break;
		}

		// Single select() for all states
		fd_set read_fds, write_fds;
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);

		if (sockfd >= 0) {
			if (state == CONNECTING)
				FD_SET(sockfd, &write_fds);
			else
				FD_SET(sockfd, &read_fds);
		}

		select(sockfd + 1, &read_fds, &write_fds, nullptr, &tv);
	}

	if (sockfd >= 0)
		state = DISCONNECTING;
	delete tuyaclient;

	return 0;
}
