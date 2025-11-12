/*
 *  Simple power usage monitor example for local Tuya client
 *
 *  Copyright 2022 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

//#define DEBUG


#define MAX_BUFFER_SIZE 1024

#include "tuyaAPI33.hpp"
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <string.h>


#include <zlib.h>


void c_error(const char *msg)
{
	perror(msg);
	exit(0);
}


int main(int argc, char *argv[])
{
	unsigned char message_buffer[MAX_BUFFER_SIZE];

	tuyaAPI33 *tuyaclient;
	tuyaclient = new tuyaAPI33();

	if (argc < 3) {
	   fprintf(stderr,"usage %s hostname tuya_id tuya_key\n", argv[0]);
	   exit(0);
	}
	if (!tuyaclient->ConnectToDevice(std::string(argv[1])))
		c_error("ERROR connecting");

	std::string device_id = std::string(argv[2]);
	std::string device_key = std::string(argv[3]);
	std::stringstream ss_payload;
	long currenttime = time(NULL) ;
	ss_payload << "{\"gwId\":\"" << device_id << "\",\"devId\":\"" << device_id << "\",\"uid\":\"" << device_id << "\",\"t\":\"" << currenttime << "\"}";
	std::string payload = ss_payload.str();

	int payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_DP_QUERY, payload, device_key);


	int numbytes = tuyaclient->send(message_buffer, payload_len);
	if (numbytes < 0)
		c_error("ERROR writing to socket");
	usleep(100000);

	numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1);
	if (numbytes < 0)
		c_error("ERROR reading from socket");

	std::string tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes, device_key);

#ifdef DEBUG
	std::cout << "dbg: raw answer: ";
	for(int i=0; i<numbytes; ++i)
		printf("%.2x", (uint8_t)message_buffer[i]);
	std::cout << "\n";
#endif
	std::cout << tuyaresponse << "\n";


	while(true)
	{
		usleep(100000);

		payload = "{\"dpId\":[1,19]}";
		payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_UPDATEDPS, payload, device_key);
		numbytes = tuyaclient->send(message_buffer, payload_len);
		if (numbytes < 0)
			c_error("ERROR writing to socket");
		usleep(100000);

		numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1);
		if (numbytes < 0)
		{
			// expect a timeout because the device will only send updates when the requested values change
			if (errno != 11)
				c_error("ERROR reading from socket");
#ifdef DEBUG
			else
				std::cout << "{\"msg\":\"timeout reached\",\"code\":11}\n";
#endif
		}
		else
		{
			tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes, device_key);
#ifdef DEBUG
			std::cout << "dbg: raw answer: ";
			for(int i=0; i<numbytes; ++i)
				printf("%.2x", (uint8_t)message_buffer[i]);
			std::cout << "\n";
#endif
			std::cout << tuyaresponse << "\n";
		}
	}

	delete tuyaclient;

	return 0;
}
