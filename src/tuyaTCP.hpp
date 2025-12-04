/*
 *	Client interface for local Tuya device access
 *
 *	This is the base TCP communication class for single device threads.
 *
 *	Both async and blocking mode (default) communication is supported,
 *	allowing straight forward single task applications to be created, as
 *	well as more advanced multi threaded monitoring applications.
 *
 *	Common functions:
 *	 - ConnectToDevice(hostname|IP_address)
 *		Opens a TCP connection with the device
 *		Returns true|false indicating success or failure
 *	 - send(buffer[], size)
 *		Sends `size` bytes of `buffer` to the device
 *		Returns `size` on success or -1 if an error occurred
 *	 - receive(buffer[], maxsize, minsize)
 *		Fills `buffer` with the device's response. The additional `minsize`
 *		parameter (used in blocking mode only) defaults to 28 to skip
 *		processing of empty responses that are returned on state changing
 *		commands.
 *		Returns number of bytes received or -1 if an error occurred
 *	 - disconnect()
 *		Closes the connection with the device
 *		Returns nothing
 *	 - getlasterror()
 *		Use this instead of referencing `errno`, which may be polluted
 *		Returns the last error state of the connection
 *
 *	Async functions:
 *	 - setAsyncMode(true|false)
 *		Enables (default) or disables async operation
 *		Returns nothing
 *	 - isSocketWritable()
 *		Returns true|false indicating if the connection is ready for writing
 *	 - isSocketReadable()
 *		Returns true|false indicating if the connection has data to be read
 *	 - getSocketState()
 *		Returns one of Tuya::TCP::Socket::value
 *	 - setSessionReady()
 *		Dummy function needed to be able to distinguish between being connected
 *		and session negotiation (API 3.4+) having been completed. Calling this
 *		method will set the SocketState to Tuya::TCP::Socket::READY from where
 *		it will alternate with Tuya::TCP::Socket::RECEIVING
 *		Does nothing if on call SocketState is not Tuya::TCP::Socket::CONNECTED
 *		Returns true|false 
 *
 *
 *	For either method, the connection requires periodic sending of a keep-alive
 *	signal. Upto a 15 second interval appears to be generally accepted. Client apps
 *	should call getSocketState() to decide what type of message the device will
 *	accept in this case:
 *	 - Tuya::TCP::Socket::READY
 *		=> data was received - you may ask for additional DPS updates
 *	 - Tuya::TCP::Socket::RECEIVING
 *		=> no data was received yet - you may only send a `HEARTBEAT` message
 *	Sending state changing commands can be done at any point in time
 *
 *
 *
 *	Copyright 2022-2026 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *	Licensed under GNU General Public License 3.0 or later.
 *	Some rights reserved. See COPYING, AUTHORS.
 *
 *	@license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#ifndef _tuyaTCP
#define _tuyaTCP

// Tuya Local Access TCP Port
#define TUYA_COMMAND_PORT 6668

#include <string>
#include <cstdint>


namespace Tuya {
  namespace TCP {
    namespace Socket {
      enum value {
        NO_SUCH_HOST,
        NO_SOCK_AVAIL,
        FAILED,
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
	READY,
        RECEIVING
      }; // enum value
    }; // namespace Socket
  }; // namespace TCP
}; // namespace Tuya


class tuyaTCP
{

public:
	tuyaTCP();
	~tuyaTCP();

	void setAsyncMode(bool async = true);
	Tuya::TCP::Socket::value getSocketState();

	virtual bool ConnectToDevice(const std::string &hostname, const uint8_t retries = 1);
	int send(unsigned char* buffer, const int size);
	int receive(unsigned char* buffer, const int maxsize, const int minsize = 28);
	int getlasterror();
	void disconnect();
	bool isSocketWritable();
	bool isSocketReadable();
	bool setSessionReady();

protected:
	Tuya::TCP::Socket::value m_socketState;

private:
	int getSocketEvents(short events, int timeout);

	int m_sockfd;
	int m_lasterror;
	bool m_asyncMode;
};

#endif

