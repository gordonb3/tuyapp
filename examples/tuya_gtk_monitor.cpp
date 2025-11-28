/*
 *  GTK+ async monitor using GIO
 *
 *  Copyright 2025 - David Woodhouse
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

#include "tuyaAPI.hpp"
#include <gtk/gtk.h>
#include <gio/gio.h>
#include <json/json.h>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

enum State {
	DISCONNECTED,
	CONNECTING,
	NEGOTIATING,
	CONNECTED
};

struct DeviceMonitor {
	std::string name;
	std::string device_id;
	std::string device_key;
	std::string address;
	tuyaAPI *api;
	GSocketClient *client;
	GSocketConnection *connection;
	GInputStream *input;
	GOutputStream *output;
	State state;
	GtkTextBuffer *buffer;
	std::ostringstream stream;
	unsigned char send_buffer[1024];
	unsigned char recv_buffer[1024];
	guint reconnect_timeout_id;
	guint heartbeat_timeout_id;
	guint negotiation_timeout_id;
	bool send_query_after_write;

	DeviceMonitor() : api(nullptr), client(nullptr), connection(nullptr),
	                  input(nullptr), output(nullptr), state(DISCONNECTED),
	                  buffer(nullptr), reconnect_timeout_id(0), heartbeat_timeout_id(0),
	                  negotiation_timeout_id(0), send_query_after_write(false) {}
};

std::map<std::string, DeviceMonitor*> devices;

void send_dp_query(DeviceMonitor *dm);
void on_session_negotiated(DeviceMonitor *dm);
gboolean reconnect_timeout(gpointer user_data);

void disconnect_device(DeviceMonitor *dm, bool auto_reconnect = true) {
	if (dm->heartbeat_timeout_id) {
		g_source_remove(dm->heartbeat_timeout_id);
		dm->heartbeat_timeout_id = 0;
	}
	if (dm->negotiation_timeout_id) {
		g_source_remove(dm->negotiation_timeout_id);
		dm->negotiation_timeout_id = 0;
	}
	if (dm->reconnect_timeout_id) {
		g_source_remove(dm->reconnect_timeout_id);
		dm->reconnect_timeout_id = 0;
	}
	if (dm->connection) {
		g_io_stream_close(G_IO_STREAM(dm->connection), nullptr, nullptr);
		g_object_unref(dm->connection);
		dm->connection = nullptr;
		dm->input = nullptr;
		dm->output = nullptr;
	}
	dm->state = DISCONNECTED;

	// Schedule reconnect if requested
	if (auto_reconnect && !dm->reconnect_timeout_id) {
		dm->reconnect_timeout_id = g_timeout_add_seconds(10, reconnect_timeout, dm);
	}
}

void append_text(DeviceMonitor *dm, const std::string &text) {
	GtkTextIter iter;
	gtk_text_buffer_get_end_iter(dm->buffer, &iter);
	gtk_text_buffer_insert(dm->buffer, &iter, text.c_str(), -1);
}

void on_write_complete(GObject *source, GAsyncResult *res, gpointer user_data) {
	DeviceMonitor *dm = (DeviceMonitor*)user_data;
	GError *error = nullptr;

	gssize bytes = g_output_stream_write_finish(G_OUTPUT_STREAM(source), res, &error);

	if (bytes < 0 && error) {
		append_text(dm, "Write error: " + std::string(error->message) + "\n");
		g_error_free(error);
		disconnect_device(dm);
	} else if (dm->send_query_after_write) {
		dm->send_query_after_write = false;
		if (dm->state == NEGOTIATING) {
			on_session_negotiated(dm);
		}
		send_dp_query(dm);
	}
}

void send_dp_query(DeviceMonitor *dm) {
	uint8_t command = TUYA_DP_QUERY;
	std::string payload = dm->api->GeneratePayload(command, dm->device_id, "");
	int len = dm->api->BuildTuyaMessage(dm->send_buffer, command, payload);

	if (len > 0) {
		g_output_stream_write_async(dm->output, dm->send_buffer, len,
		                            G_PRIORITY_DEFAULT, nullptr, on_write_complete, dm);
	}
}

void on_read_ready(GObject *source, GAsyncResult *res, gpointer user_data) {
	DeviceMonitor *dm = (DeviceMonitor*)user_data;
	GError *error = nullptr;

	gssize bytes = g_input_stream_read_finish(G_INPUT_STREAM(source), res, &error);

	if (bytes > 0) {
		std::string response = dm->api->DecodeTuyaMessage(dm->recv_buffer, bytes);
		append_text(dm, "Received: " + response + "\n");

		// Continue reading
		g_input_stream_read_async(dm->input, dm->recv_buffer, sizeof(dm->send_buffer),
		                          G_PRIORITY_DEFAULT, nullptr, on_read_ready, dm);
	} else if (bytes == 0) {
		if (dm->state != DISCONNECTED) {
			append_text(dm, "Connection closed by remote\n");
			disconnect_device(dm);
		}
	} else if (error) {
		if (dm->state != DISCONNECTED) {
			append_text(dm, "Read error: " + std::string(error->message) + "\n");
			disconnect_device(dm);
		}
		g_error_free(error);
	}
}

gboolean send_heartbeat(gpointer user_data) {
	DeviceMonitor *dm = (DeviceMonitor*)user_data;

	if (dm->state == CONNECTED) {
		int len = dm->api->BuildTuyaMessage(dm->send_buffer, TUYA_HEART_BEAT, "");
		if (len > 0) {
			g_output_stream_write_async(dm->output, dm->send_buffer, len,
			                            G_PRIORITY_DEFAULT, nullptr, nullptr, nullptr);
		}
	}
	return G_SOURCE_CONTINUE;
}

void on_session_negotiated(DeviceMonitor *dm) {
	dm->state = CONNECTED;
	append_text(dm, "Session negotiated\n");

	// Start heartbeat timer (every 5 seconds)
	dm->heartbeat_timeout_id = g_timeout_add_seconds(5, send_heartbeat, dm);

	// Start reading
	g_input_stream_read_async(dm->input, dm->recv_buffer, sizeof(dm->send_buffer),
	                          G_PRIORITY_DEFAULT, nullptr, on_read_ready, dm);
}

gboolean negotiation_timeout(gpointer user_data) {
	DeviceMonitor *dm = (DeviceMonitor*)user_data;
	append_text(dm, "Session negotiation timeout\n");
	dm->negotiation_timeout_id = 0;
	disconnect_device(dm);
	return G_SOURCE_REMOVE;
}

void negotiate_session_step(DeviceMonitor *dm);

void on_session_read(GObject *source, GAsyncResult *res, gpointer user_data) {
	DeviceMonitor *dm = (DeviceMonitor*)user_data;
	GError *error = nullptr;

	gssize bytes = g_input_stream_read_finish(G_INPUT_STREAM(source), res, &error);

	if (bytes > 0) {
		if (dm->negotiation_timeout_id) {
			g_source_remove(dm->negotiation_timeout_id);
			dm->negotiation_timeout_id = 0;
		}

		dm->api->DecodeSessionMessage(dm->recv_buffer, bytes);

		if (dm->api->isSessionEstablished()) {
			on_session_negotiated(dm);
		} else {
			negotiate_session_step(dm);
		}
	} else if (error) {
		append_text(dm, "Session read error: " + std::string(error->message) + "\n");
		g_error_free(error);
		disconnect_device(dm);
	}
}

void negotiate_session_step(DeviceMonitor *dm) {
	int len = dm->api->BuildSessionMessage(dm->send_buffer);

	if (len == 0) {
		// No session negotiation needed (protocols < 3.4)
		on_session_negotiated(dm);
		return;
	}

	if (len > 0) {
		// Check if session is now established (after sending final message)
		if (dm->api->isSessionEstablished()) {
			dm->send_query_after_write = true;
			g_output_stream_write_async(dm->output, dm->send_buffer, len,
			                            G_PRIORITY_DEFAULT, nullptr, on_write_complete, dm);
		} else {
			g_output_stream_write_async(dm->output, dm->send_buffer, len,
			                            G_PRIORITY_DEFAULT, nullptr, nullptr, nullptr);
			// Set timeout for negotiation response (10 seconds)
			if (!dm->negotiation_timeout_id) {
				dm->negotiation_timeout_id = g_timeout_add_seconds(10, negotiation_timeout, dm);
			}
			// Read response asynchronously
			g_input_stream_read_async(dm->input, dm->recv_buffer, sizeof(dm->send_buffer),
			                          G_PRIORITY_DEFAULT, nullptr, on_session_read, dm);
		}
	} else {
		append_text(dm, "BuildSessionMessage failed\n");
		disconnect_device(dm);
	}
}

void on_connected(GObject *source, GAsyncResult *res, gpointer user_data) {
	DeviceMonitor *dm = (DeviceMonitor*)user_data;
	GError *error = nullptr;

	dm->connection = g_socket_client_connect_to_host_finish(G_SOCKET_CLIENT(source), res, &error);

	if (dm->connection) {
		append_text(dm, "Connected\n");
		dm->state = NEGOTIATING;

		// Stop reconnect timer
		if (dm->reconnect_timeout_id) {
			g_source_remove(dm->reconnect_timeout_id);
			dm->reconnect_timeout_id = 0;
		}

		dm->input = g_io_stream_get_input_stream(G_IO_STREAM(dm->connection));
		dm->output = g_io_stream_get_output_stream(G_IO_STREAM(dm->connection));

		dm->api->SetEncryptionKey(dm->device_key);
		negotiate_session_step(dm);
	} else {
		append_text(dm, "Connection failed: " + std::string(error->message) + "\n");
		g_error_free(error);
		disconnect_device(dm);
	}
}

gboolean reconnect_timeout(gpointer user_data) {
	DeviceMonitor *dm = (DeviceMonitor*)user_data;

	if (dm->state == DISCONNECTED) {
		append_text(dm, "Connecting to " + dm->address + "...\n");
		dm->state = CONNECTING;

		g_socket_client_connect_to_host_async(dm->client, dm->address.c_str(), 6668,
		                                      nullptr, on_connected, dm);
	}

	return G_SOURCE_CONTINUE;
}

bool get_device_by_name(const std::string name, std::string &id, std::string &key, std::string &address, std::string &version) {
	std::ifstream myfile(SECRETSFILE);
	if (!myfile.is_open())
		return false;

	std::string content((std::istreambuf_iterator<char>(myfile)), std::istreambuf_iterator<char>());
	myfile.close();

	Json::Value jRoot;
	Json::CharReaderBuilder jBuilder;
	std::unique_ptr<Json::CharReader> jReader(jBuilder.newCharReader());
	std::string errors;

	if (!jReader->parse(content.c_str(), content.c_str() + content.size(), &jRoot, &errors))
		return false;

	if (!jRoot.isMember("devices") || !jRoot["devices"].isArray())
		return false;

	for (const auto &device : jRoot["devices"]) {
		if (device["name"].asString() == name) {
			id = device["id"].asString();
			key = device["key"].asString();
			address = device["address"].asString();
			version = device["version"].asString();
			return true;
		}
	}

	return false;
}

int main(int argc, char *argv[]) {
	gtk_init(&argc, &argv);

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <device_name> [device_name2 ...]\n";
		return 1;
	}

	GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(window), "Tuya Device Monitor");
	gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), nullptr);

	GtkWidget *notebook = gtk_notebook_new();
	gtk_container_add(GTK_CONTAINER(window), notebook);

	for (int i = 1; i < argc; i++) {
		std::string name = argv[i];
		std::string id, key, address, version;

		if (!get_device_by_name(name, id, key, address, version)) {
			std::cerr << "Device " << name << " not found\n";
			continue;
		}

		DeviceMonitor *dm = new DeviceMonitor();
		dm->name = name;
		dm->device_id = id;
		dm->device_key = key;
		dm->address = address;
		dm->api = tuyaAPI::create(version);
		dm->client = g_socket_client_new();

		GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

		GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
		GtkWidget *connect_btn = gtk_button_new_with_label("Connect");
		GtkWidget *disconnect_btn = gtk_button_new_with_label("Disconnect");
		gtk_box_pack_start(GTK_BOX(button_box), connect_btn, FALSE, FALSE, 5);
		gtk_box_pack_start(GTK_BOX(button_box), disconnect_btn, FALSE, FALSE, 5);
		gtk_box_pack_start(GTK_BOX(vbox), button_box, FALSE, FALSE, 5);

		GtkWidget *scrolled = gtk_scrolled_window_new(nullptr, nullptr);
		GtkWidget *textview = gtk_text_view_new();
		gtk_text_view_set_editable(GTK_TEXT_VIEW(textview), FALSE);
		dm->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
		gtk_container_add(GTK_CONTAINER(scrolled), textview);
		gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

		g_signal_connect(connect_btn, "clicked", G_CALLBACK(+[](GtkWidget*, gpointer data) {
			DeviceMonitor *dm = (DeviceMonitor*)data;
			if (dm->state == DISCONNECTED) {
				reconnect_timeout(dm);
			}
		}), dm);

		g_signal_connect(disconnect_btn, "clicked", G_CALLBACK(+[](GtkWidget*, gpointer data) {
			DeviceMonitor *dm = (DeviceMonitor*)data;
			disconnect_device(dm, false);
		}), dm);

		gtk_notebook_append_page(GTK_NOTEBOOK(notebook), vbox, gtk_label_new(name.c_str()));

		devices[name] = dm;

		reconnect_timeout(dm);
	}

	gtk_widget_show_all(window);
	gtk_main();

	return 0;
}
