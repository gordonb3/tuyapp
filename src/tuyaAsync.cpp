#include "tuyaAsync.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <iostream>
#include <sstream>

tuyaAsync::tuyaAsync(const std::string &version, const std::string &id,
                     const std::string &key, const std::string &addr,
                     std::ostream *out)
	: m_api(nullptr)
	, m_sockfd(-1)
	, m_state(DISCONNECTED)
	, m_last_rx_time(0)
	, m_state_start_time(0)
	, m_last_connect_attempt(0)
	, m_device_id(id)
	, m_device_key(key)
	, m_device_address(addr)
	, m_device_version(version)
	, m_out(out ? out : &std::cout)
{
	m_api = tuyaAPI::create(version);
}

tuyaAsync::~tuyaAsync()
{
	if (m_sockfd >= 0)
		close(m_sockfd);
	delete m_api;
}

bool tuyaAsync::wants_read() const
{
	return m_state != CONNECTING && m_sockfd >= 0;
}

bool tuyaAsync::wants_write() const
{
	return m_state == CONNECTING && m_sockfd >= 0;
}

void tuyaAsync::loop(struct timeval &tv)
{
	time_t now = time(NULL);

	switch (m_state)
	{
	case DISCONNECTED:
	{
		// Only attempt connect if enough time has passed since last attempt
		if (now - m_last_connect_attempt < 10)
			break;

		*m_out << "Connecting to " << m_device_address << ":6668...\n";
		m_last_connect_attempt = now;

		// Reset API state for new connection
		delete m_api;
		m_api = tuyaAPI::create(m_device_version);
		if (!m_api) {
			*m_out << "Failed to create API\n";
			break;
		}

		struct addrinfo hints = {}, *result;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICHOST;

		int err = getaddrinfo(m_device_address.c_str(), "6668", &hints, &result);
		if (err != 0) {
			*m_out << "Failed to resolve address: " << gai_strerror(err) << "\n";
			break;
		}

		m_sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
		if (m_sockfd < 0) {
			*m_out << "Failed to create socket\n";
			freeaddrinfo(result);
			break;
		}

		fcntl(m_sockfd, F_SETFL, O_NONBLOCK);

		err = connect(m_sockfd, result->ai_addr, result->ai_addrlen);
		freeaddrinfo(result);

		if (err != 0 && errno != EINPROGRESS) {
			*m_out << "Connect failed: " << strerror(errno) << "\n";
			m_state = DISCONNECTING;
			break;
		}
#ifdef DEBUG
		*m_out << "Connect initiated (EINPROGRESS)\n";
#endif
		m_state = CONNECTING;
		m_state_start_time = now;
		break;
	}

	case DISCONNECTING:
		close(m_sockfd);
		m_sockfd = -1;
		m_state = DISCONNECTED;
		break;

	case CONNECTING:
	{
		// Check for timeout
		if (now - m_state_start_time > 5) {
			*m_out << "Connection timeout\n";
			m_state = DISCONNECTING;
			break;
		}

		// Check if socket is writable (connection complete)
		fd_set write_fds;
		FD_ZERO(&write_fds);
		FD_SET(m_sockfd, &write_fds);
		struct timeval tv_zero = {0, 0};
		int ret = select(m_sockfd + 1, nullptr, &write_fds, nullptr, &tv_zero);

		if (ret <= 0 || !FD_ISSET(m_sockfd, &write_fds))
			break;  // Not ready yet

		// Socket is writable - check if connection succeeded
		int error = 0;
		socklen_t len = sizeof(error);
		if (getsockopt(m_sockfd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
			*m_out << "Connection failed: " << strerror(error) << "\n";
			m_state = DISCONNECTING;
			break;
		}

		*m_out << "Connected!\n";

		// Set encryption key now that we're connected
		m_api->SetEncryptionKey(m_device_key);

		// Start negotiation
		unsigned char session_msg[1024];
		int session_len = m_api->BuildSessionMessage(session_msg);
		if (session_len < 0) {
			*m_out << "Failed to build session message\n";
			m_state = DISCONNECTING;
			break;
		}

#ifdef DEBUG
		if (session_len > 0)
			*m_out << "Built session message: " << session_len << " bytes\n";
		else
			*m_out << "No negotiation needed\n";
#endif
		m_state = NEGOTIATING;
		m_state_start_time = now;
		m_last_rx_time = now;

		// Transitioned to NEGOTIATING - send first packet if we have one
		if (session_len > 0) {
			ssize_t sent = write(m_sockfd, session_msg, session_len);
			if (sent > 0) {
#ifdef DEBUG
				*m_out << "Sent negotiation packet: " << sent << " bytes\n";
#endif
			} else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
				*m_out << "Write error: " << strerror(errno) << "\n";
				m_state = DISCONNECTING;
			break;
			}
		}
		break;
	}

	case NEGOTIATING:
	{
		// Check for timeout
		if (now - m_state_start_time > 5) {
			*m_out << "Negotiation timeout\n";
			m_state = DISCONNECTING;
			break;
		}

		// If not yet established, do negotiation work
		if (!m_api->isSessionEstablished()) {
			// Read response
			ssize_t len = read(m_sockfd, m_message_buffer, sizeof(m_message_buffer));
			if (len > 0) {
#ifdef DEBUG
				*m_out << "Received negotiation response: " << len << " bytes\n";
#endif
				m_api->DecodeSessionMessage(m_message_buffer, len);

				if (m_api->isSessionEstablished()) {
					*m_out << "Negotiation complete\n";
					m_state = CONNECTED;
					m_last_rx_time = now;
				} else {
					unsigned char session_msg[1024];
					int session_len = m_api->BuildSessionMessage(session_msg);
					if (session_len < 0) {
						*m_out << "Negotiation failed\n";
						m_state = DISCONNECTING;
			break;
					} else if (session_len > 0) {
						// Send immediately
						ssize_t sent = write(m_sockfd, session_msg, session_len);
						if (sent > 0) {
#ifdef DEBUG
							*m_out << "Sent negotiation packet: " << sent << " bytes\n";
#endif

							// Check if negotiation complete
							if (m_api->isSessionEstablished()) {
								*m_out << "Negotiation complete\n";
								m_state = CONNECTED;
								m_last_rx_time = now;
							}
						} else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
							*m_out << "Write error: " << strerror(errno) << "\n";
							m_state = DISCONNECTING;
			break;
						}
					}
				}
			} else if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
				*m_out << "Read error: " << strerror(errno) << "\n";
				m_state = DISCONNECTING;
			break;
			}
		}

		// Transitioned to CONNECTED - send initial DP query
		if (m_state == CONNECTED) {
			uint8_t command = TUYA_DP_QUERY;
			std::string payload = m_api->GeneratePayload(command, m_device_id, "");

			int len = m_api->BuildTuyaMessage(m_message_buffer, command, payload);
			if (len > 0) {
				ssize_t sent = write(m_sockfd, m_message_buffer, len);
				if (sent == len) {
					*m_out << "Sent DP query\n";
					*m_out << "Monitoring for updates (Ctrl-C to exit)...\n";
				}
			}
		}
		break;
	}

	case CONNECTED:
	{
		// Check for incoming data
		ssize_t len = read(m_sockfd, m_message_buffer, sizeof(m_message_buffer));
		if (len > 0) {
			m_last_rx_time = now;
			std::string decoded = m_api->DecodeTuyaMessage(m_message_buffer, len);
			if (!decoded.empty()) {
				*m_out << "Received: " << decoded << "\n";
			}
		} else if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			*m_out << "Read error: " << strerror(errno) << "\n";
			m_state = DISCONNECTING;
			break;
		} else if (len == 0) {
			*m_out << "Connection closed by device\n";
			m_state = DISCONNECTING;
			break;
		}

		// Send heartbeat if no data for 5 seconds
		if (now - m_last_rx_time > 5) {
			int len = m_api->BuildTuyaMessage(m_message_buffer, TUYA_HEART_BEAT, "");
			if (len > 0) {
				ssize_t sent = write(m_sockfd, m_message_buffer, len);
				if (sent == len) {
					*m_out << "Sent heartbeat\n";
					m_last_rx_time = now;
				}
			}
		}
		break;
	}
	}

	// Calculate timeout based on state
	switch (m_state) {
	case DISCONNECTED:
		tv.tv_sec = 10 - (now - m_last_connect_attempt);  // 10s between reconnect attempts
		if (tv.tv_sec < 0) tv.tv_sec = 0;
		tv.tv_usec = 0;
		break;
	case CONNECTING:
		tv.tv_sec = 5 - (now - m_state_start_time);  // 5 second connect timeout
		if (tv.tv_sec < 0) tv.tv_sec = 0;
		tv.tv_usec = 0;
		break;
	case NEGOTIATING:
		tv.tv_sec = 5 - (now - m_state_start_time);  // 5 second negotiation timeout
		if (tv.tv_sec < 0) tv.tv_sec = 0;
		tv.tv_usec = 0;
		break;
	case CONNECTED:
		tv.tv_sec = 5 - (now - m_last_rx_time);  // Wake to send heartbeat
		if (tv.tv_sec < 0) tv.tv_sec = 0;
		tv.tv_usec = 0;
		break;
	case DISCONNECTING:
		tv.tv_sec = 0;  // Immediate
		tv.tv_usec = 0;
		break;
	}
}
