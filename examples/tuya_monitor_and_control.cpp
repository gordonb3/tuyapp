/*
 *  Monitor thread with command input example for local Tuya client
 *
 *  This example creates a looping thread in which each pass executes at most
 *  one async network operation, writing any information shared by the device
 *  to screen. Triggering the device to output information can be done either
 *  by clicking the on|off button on the device itself, or by issuing one of
 *  the following commands on the command line:
 *
 *   '0' to switch off
 *   '1' to switch on
 *   't' to toggle on|off (has a 1 second delay)
 *   'i' to request datapoints
 *   'q' to quit
 * 
 *  Note: you must hit 'Enter' for the commands to actually be sent to the app
 * 
 *
 *  Copyright 2025-2026 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */



// minimum message size to consider as a valid response
// set at least to 30 if you are relying on the internal state flags
// Tuya::TCP::Socket::READY and Tuya::TCP::Socket::RECEIVING
// example default is 76 in order to drop invalid packets from tinytuya fake3.5 device
#define MINBYTES 76

// sleep time in milliseconds between running tasks
// you can play with this to examine the effect on CPU load
#define SLEEPTIME 10

// time in seconds between sending heart beat
#define HEARTBEATTIME 10

// time in seconds bebefore declaring command timeout
#define COMMANDTIMEOUT 1

// time in seconds bebefore declaring connect timeout
#define CONNECTTIMEOUT 5



/******************************************************************************/

#include "tuyaAPI.hpp"
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <json/json.h>

#include <fstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <poll.h>

#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE 1024
#endif

#ifndef SECRETSFILE
#define SECRETSFILE "tuya-devices.json"
#endif

#ifdef APPDEBUG
#include <iostream>
#endif


bool StopRequested;
std::string m_szDeviceID, m_szDeviceKey, m_szDeviceAddress;
tuyaAPI *m_tuyaclient;
long m_timeout_at;
uint32_t m_cycle_counter;


void do_something_with_response(std::string szResponse)
{
	// this is where data gets sent to for doing stuff
	if (!szResponse.empty())
		std::cout << szResponse << "\n";

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


void SendCommand(char cmd)
{
	uint8_t command;
	std::string szDPS;
	unsigned char cMessageBuffer[MAX_BUFFER_SIZE];
	std::string szPayload;
	int payload_len;
	struct timespec now;

	if (cmd == 'i')
	{
/*
		if (m_tuyaclient->getProtocol() >= tuyaAPI::Protocol::v35)
			command = TUYA_DP_QUERY_NEW;
		else
*/
			command = TUYA_DP_QUERY;
		std::string szPayload = m_tuyaclient->GeneratePayload(command, m_szDeviceID, "");
		int payload_len = m_tuyaclient->BuildTuyaMessage(cMessageBuffer, command, szPayload, m_szDeviceKey);
		if (payload_len > 0)
		{
			if (m_tuyaclient->send(cMessageBuffer, payload_len) < 0)
				std::cout << "Failed send of DP_QUERY\n";
		}
		clock_gettime(CLOCK_MONOTONIC, &now);
		m_timeout_at = now.tv_sec*1000 + now.tv_nsec/1000000 + 10000;	// 10 seconds advance
		return;
	}

	if (cmd == '0')
		szDPS = "{\"1\":false}";
	else if (cmd == '1')
		szDPS = "{\"1\":true}";
	else if (cmd == 't')
		szDPS = "{\"9\":1}";
	else return;

	if (m_tuyaclient->getProtocol() >= tuyaAPI::Protocol::v34)
		command = TUYA_CONTROL_NEW;
	else
		command = TUYA_CONTROL;

	szPayload = m_tuyaclient->GeneratePayload(command, m_szDeviceID, szDPS);
	payload_len = m_tuyaclient->BuildTuyaMessage(cMessageBuffer, command, szPayload, m_szDeviceKey);
	if (payload_len > 0)
	{
		if (m_tuyaclient->send(cMessageBuffer, payload_len) < 0)
			std::cout << "Failed send of DP_QUERY\n";
	}
	clock_gettime(CLOCK_MONOTONIC, &now);
	m_timeout_at = now.tv_sec*1000 + now.tv_nsec/1000000 + COMMANDTIMEOUT*1000;
}


void RunSingleTask()
{
	switch (m_tuyaclient->getSocketState())
	{

		case Tuya::TCP::Socket::NO_SUCH_HOST:
			{
				std::cout << "Error: host " << m_szDeviceAddress << " not found\n";
				StopRequested = true;
				return;
			}
		case Tuya::TCP::Socket::NO_SOCK_AVAIL:
			{
				std::cout << "Error: no socket available\n";
				StopRequested = true;
				return;
			}
		case Tuya::TCP::Socket::FAILED:
			{
				std::cout << "Error: connection failed\n";
				StopRequested = true;
				return;
			}

		case Tuya::TCP::Socket::DISCONNECTED:
			{
#ifdef APPDEBUG
				std::cout << m_cycle_counter << ": Connecting to " << m_szDeviceAddress << ":6668...\n";
#endif
				m_tuyaclient->ConnectToDevice(m_szDeviceAddress);
				struct timespec now;
				clock_gettime(CLOCK_MONOTONIC, &now);
				m_timeout_at = now.tv_sec*1000 + now.tv_nsec/1000000 + CONNECTTIMEOUT*1000;
				break;
			}

		case Tuya::TCP::Socket::CONNECTING:
			{
				if (m_tuyaclient->isConnected())
				{
#ifdef APPDEBUG
					std::cout << m_cycle_counter << ": Connect successful\n";
#endif
					break;
				}
				else
				{
					struct timespec now;
					clock_gettime(CLOCK_MONOTONIC, &now);
					if (m_timeout_at <= (now.tv_sec*1000 + now.tv_nsec/1000000))
					{
						std::cout << "Error: connect timed out\n";
						m_tuyaclient->disconnect();
						return;
					}
				}
				break;
			}

		case Tuya::TCP::Socket::CONNECTED:
			{
				// negotiate session
				switch (m_tuyaclient->getSessionState())
				{
					case Tuya::Session::INVALID:
						{
#ifdef APPDEBUG
							std::cout << m_cycle_counter << ": Starting session negotiation\n";
#endif
							m_tuyaclient->NegotiateSessionStart(m_szDeviceKey);
							struct timespec now;
							clock_gettime(CLOCK_MONOTONIC, &now);
							m_timeout_at = now.tv_sec*1000 + now.tv_nsec/1000000 + COMMANDTIMEOUT*1000;
							break;
						}
					case Tuya::Session::STARTING:
						{
							if (m_tuyaclient->isSocketReadable())
							{
								unsigned char buffer[256];
								int numbytes = m_tuyaclient->receive(buffer,255);
								m_tuyaclient->NegotiateSessionFinalize(buffer, numbytes, m_szDeviceKey);
							}
							else
							{
							struct timespec now;
								clock_gettime(CLOCK_MONOTONIC, &now);
								if (m_timeout_at <= (now.tv_sec*1000 + now.tv_nsec/1000000))
								{
									std::cout << "Error: session negotiation timed out\n";
								}
							}
							break;
						}
					case Tuya::Session::FINALIZING:
						{
							// ToDo: is there ever a response on the finalize action?
							break;
						}
					case Tuya::Session::ESTABLISHED:
					default:
						{
							m_tuyaclient->setSessionReady();
#ifdef APPDEBUG
							std::cout << m_cycle_counter << ": Session established\n";
#endif
							// request data points
							SendCommand('i');
							break;
						}
				}
				break;
			}

		case Tuya::TCP::Socket::READY:
			{
				// make new request for data point updates for switch state, power and voltage
#ifdef APPDEBUG
				std::cout << m_cycle_counter << ": sending new request\n";
#endif
				unsigned char cMessageBuffer[MAX_BUFFER_SIZE];
				std::string szPayload = "{\"dpId\":[1,19,20]}";
				int payload_len = m_tuyaclient->BuildTuyaMessage(cMessageBuffer, TUYA_UPDATEDPS, szPayload, m_szDeviceKey);
				if (payload_len > 0)
				{
					if (m_tuyaclient->send(cMessageBuffer, payload_len) < 0)
						std::cout << "Failed send of UPDATEDPS\n";
				}
				struct timespec now;
				clock_gettime(CLOCK_MONOTONIC, &now);
				m_timeout_at = now.tv_sec*1000 + now.tv_nsec/1000000 + HEARTBEATTIME*1000;
				break;
			}

		case Tuya::TCP::Socket::RECEIVING:
			{
				if (m_tuyaclient->isSocketReadable())
				{
					unsigned char cMessageBuffer[MAX_BUFFER_SIZE];
					int numbytes = m_tuyaclient->receive(cMessageBuffer, MAX_BUFFER_SIZE - 1, MINBYTES);
					std::string tuyaresponse = m_tuyaclient->DecodeTuyaMessage(cMessageBuffer, numbytes, m_szDeviceKey);
	
					// send response to "smart" function
					do_something_with_response(tuyaresponse);
					break;
				}
				struct timespec now;
				clock_gettime(CLOCK_MONOTONIC, &now);
				if (m_timeout_at <= (now.tv_sec*1000 + now.tv_nsec/1000000))
				{
					// send heart beat	
#ifdef APPDEBUG
					std::cout << m_cycle_counter << ": sending HEART_BEAT\n";
#endif
					unsigned char cMessageBuffer[MAX_BUFFER_SIZE];
					std::string szPayload = m_tuyaclient->GeneratePayload(TUYA_HEART_BEAT, m_szDeviceID, "");
					int payload_len = m_tuyaclient->BuildTuyaMessage(cMessageBuffer, TUYA_HEART_BEAT, szPayload, m_szDeviceKey);
					if (payload_len > 0)
					{
						if (m_tuyaclient->send(cMessageBuffer, payload_len) < 0)
							std::cout << "Failed send of HEART_BEAT\n";
					}
					clock_gettime(CLOCK_MONOTONIC, &now);
					m_timeout_at = now.tv_sec*1000 + now.tv_nsec/1000000 + HEARTBEATTIME*1000;
				}
				break;
			}
		
		default:
			break;
	}
}


void DoWork(std::string devicename)
{
	StopRequested = false;
	std::string device_version;
	if (!get_device_by_name(devicename, m_szDeviceID, m_szDeviceKey, m_szDeviceAddress, device_version))
	{
		std::cout << "Error: Device unknown\n";
		StopRequested = true;
		return;
	}
#ifdef APPDEBUG
	std::cout << "Create tuyaAPI " << device_version << " object for device " << devicename  << "\n";
#endif

	m_tuyaclient = tuyaAPI::create(device_version);
	m_tuyaclient->setAsyncMode();

	m_cycle_counter = 0;
	while (!StopRequested)
	{
		m_cycle_counter++;
		RunSingleTask();
		std::this_thread::sleep_for(std::chrono::milliseconds(SLEEPTIME));
	}
}


int main(int argc, char *argv[])
{
	if (argc < 2) {
	   fprintf(stderr,"usage %s hostname\n", argv[0]);
	   exit(0);
	}

	std::thread* WorkerThread = new std::thread(DoWork, std::string(argv[1]));

	std::cout << "Press '1' to switch on, '0' to switch off, 't' to toggle, 'i' to get datapoints, 'q' to quit\n";
	std::cout << "Enter to confirm command\n\n";


	struct pollfd pfd = { STDIN_FILENO, POLLIN, 0 };
	char c = '\0';
	int ret = 0;
	while (c != 'q')
	{
	        ret = poll(&pfd, 1, 100);  // timeout of 100ms
	        if(ret == 1) // there is something to read
		{
			std::cin.get(c);
			SendCommand(c);
		}
		else if(ret == -1)
		{
			std::cout << "Error: " << strerror(errno) << std::endl;
		}
		if (StopRequested)
			break;
	}
	StopRequested = true;

	WorkerThread->join();

}

