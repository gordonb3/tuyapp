/*
 *  GTK+ async monitor using tuyaAsync class with glib mainloop
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

#include "tuyaAsync.hpp"
#include <gtk/gtk.h>
#include <json/json.h>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

struct DeviceWidget {
	tuyaAsync *device;
	GtkWidget *textview;
	GtkTextBuffer *buffer;
	guint io_watch;
	guint timeout_id;
	std::string name;
	std::ostringstream stream;
};

std::map<tuyaAsync*, DeviceWidget*> device_map;

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

void append_text(DeviceWidget *dw, const char *text)
{
	GtkTextIter end;
	gtk_text_buffer_get_end_iter(dw->buffer, &end);
	gtk_text_buffer_insert(dw->buffer, &end, text, -1);

	GtkTextMark *mark = gtk_text_buffer_get_insert(dw->buffer);
	gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(dw->textview), mark, 0.0, FALSE, 0.0, 0.0);
}

void flush_stream(DeviceWidget *dw)
{
	std::string output = dw->stream.str();
	if (!output.empty()) {
		append_text(dw, output.c_str());
		dw->stream.str("");
		dw->stream.clear();
	}
}

gboolean io_callback(GIOChannel *source, GIOCondition condition, gpointer data)
{
	DeviceWidget *dw = (DeviceWidget*)data;
	struct timeval tv = {0, 0};
	dw->device->loop(tv);
	flush_stream(dw);
	return TRUE;
}

gboolean timeout_callback(gpointer data)
{
	DeviceWidget *dw = (DeviceWidget*)data;
	struct timeval tv = {0, 0};
	dw->device->loop(tv);
	flush_stream(dw);

	if (dw->io_watch) {
		g_source_remove(dw->io_watch);
		dw->io_watch = 0;
	}

	int fd = dw->device->get_fd();
	if (fd >= 0) {
		GIOChannel *channel = g_io_channel_unix_new(fd);
		GIOCondition cond = (GIOCondition)0;
		if (dw->device->wants_read())
			cond = (GIOCondition)(cond | G_IO_IN);
		if (dw->device->wants_write())
			cond = (GIOCondition)(cond | G_IO_OUT);
		if (cond)
			dw->io_watch = g_io_add_watch(channel, cond, io_callback, dw);
		g_io_channel_unref(channel);
	}

	if (tv.tv_sec > 0 || tv.tv_usec > 0) {
		dw->timeout_id = g_timeout_add(tv.tv_sec * 1000 + tv.tv_usec / 1000, timeout_callback, dw);
		return FALSE;
	}

	return TRUE;
}

int main(int argc, char *argv[])
{
	gtk_init(&argc, &argv);

	if (argc < 2) {
		fprintf(stderr,"usage %s hostname [hostname2 ...]\n", argv[0]);
		exit(0);
	}

	GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(window), "Tuya Device Monitor");
	gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

	GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	gtk_container_add(GTK_CONTAINER(window), vbox);

	// Create widgets for each device
	for (int i = 1; i < argc; i++) {
		std::string device_id, device_key, device_address, device_version;
		if (!get_device_by_name(std::string(argv[i]), device_id, device_key, device_address, device_version))
		{
			g_printerr("Error: Device %s unknown\n", argv[i]);
			continue;
		}

		DeviceWidget *dw = new DeviceWidget;
		dw->name = argv[i];
		dw->device = new tuyaAsync(device_version, device_id, device_key, device_address, &dw->stream);
		dw->io_watch = 0;

		GtkWidget *frame = gtk_frame_new(argv[i]);
		gtk_box_pack_start(GTK_BOX(vbox), frame, TRUE, TRUE, 0);

		GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
		gtk_container_add(GTK_CONTAINER(frame), scrolled);

		dw->textview = gtk_text_view_new();
		gtk_text_view_set_editable(GTK_TEXT_VIEW(dw->textview), FALSE);
		gtk_container_add(GTK_CONTAINER(scrolled), dw->textview);

		dw->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(dw->textview));

		device_map[dw->device] = dw;

		// Start timeout
		dw->timeout_id = g_timeout_add(100, timeout_callback, dw);
	}

	gtk_widget_show_all(window);
	gtk_main();

	// Cleanup
	for (auto &pair : device_map) {
		DeviceWidget *dw = pair.second;
		if (dw->io_watch)
			g_source_remove(dw->io_watch);
		if (dw->timeout_id)
			g_source_remove(dw->timeout_id);
		delete dw->device;
		delete dw;
	}

	return 0;
}
