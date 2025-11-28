#ifndef TUYAASYNC_HPP
#define TUYAASYNC_HPP

#include "tuyaAPI.hpp"
#include <string>
#include <sys/time.h>
#include <ostream>

class tuyaAsync {
public:
	tuyaAsync(const std::string &version, const std::string &id,
	          const std::string &key, const std::string &addr,
	          std::ostream *out = nullptr);
	~tuyaAsync();

	// Called by application's event loop
	void loop(struct timeval &tv);

	int get_fd() const { return m_sockfd; }
	bool wants_read() const;
	bool wants_write() const;

private:
	enum State {
		DISCONNECTED,
		CONNECTING,
		NEGOTIATING,
		CONNECTED,
		DISCONNECTING
	};

	tuyaAPI *m_api;
	int m_sockfd;
	State m_state;
	time_t m_last_rx_time;
	time_t m_state_start_time;
	time_t m_last_connect_attempt;
	unsigned char m_message_buffer[1024];
	std::string m_device_id;
	std::string m_device_key;
	std::string m_device_address;
	std::string m_device_version;
	std::ostream *m_out;
};

#endif // TUYAASYNC_HPP
