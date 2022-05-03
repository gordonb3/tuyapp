//#define DEBUG


#define MAX_BUFFER_SIZE 1024
#define TUYA_COMMAND_PORT 6668

#include "tuyaAPI33.hpp"
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <string.h>

#include <fstream>



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

	if (argc < 5) {
	   fprintf(stderr,"usage %s hostname tuya_id tuya_key on|off|toggle [countdown]\n", argv[0]);
	   exit(0);
	}
	if (!tuyaclient->ConnectToDevice(std::string(argv[1]), TUYA_COMMAND_PORT))
		c_error("ERROR connecting");

	std::string device_id = std::string(argv[2]);
	std::string device_key = std::string(argv[3]);
	std::string s_switchstate = std::string(argv[4]);
	int countdown = 0;
	if (argc > 5)
		countdown = atoi(argv[5]);

	// get switch status
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
			c_error("ERROR fetching current switch state");
	}


	ss_payload.str(std::string());
	ss_payload << "{\"devId\":\"" << device_id << "\",\"uid\":\"" << device_id << "\",\"dps\":{\"1\":";
	if (switchstate)
		ss_payload << "true";
	else
		ss_payload << "false";
	if (countdown)
		ss_payload << ",\"9\":" << countdown;
	ss_payload <<  "},\"t\":\"" << currenttime << "\"}";
	payload = ss_payload.str();

#ifdef DEBUG
	std::cout << "building switch payload: " << payload << "\n";
#endif

	payload_len = tuyaclient->BuildTuyaMessage(message_buffer, TUYA_CONTROL, payload, device_key);

#ifdef DEBUG
		std::cout << "sending message: ";
		for(int i=0; i<numbytes; ++i)
			printf("%.2x", (uint8_t)message_buffer[i]);
		std::cout << "\n";
#endif

	numbytes = tuyaclient->send(message_buffer, payload_len);
	if (numbytes < 0)
		c_error("ERROR writing to socket");
	usleep(100000);

	numbytes = tuyaclient->receive(message_buffer, MAX_BUFFER_SIZE - 1);
	if (numbytes < 0)
		c_error("ERROR reading from socket");


	tuyaresponse = tuyaclient->DecodeTuyaMessage(message_buffer, numbytes, device_key);
#ifdef DEBUG
	std::cout << "dbg: raw answer: ";
	for(int i=0; i<numbytes; ++i)
		printf("%.2x", (uint8_t)message_buffer[i]);
	std::cout << "\n";
	std::cout << "decoded answer: " << tuyaresponse << "\n";
#endif

	delete tuyaclient;

	return 0;
}

