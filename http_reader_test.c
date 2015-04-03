/*
** Copyright (c) 2015, Yaler GmbH, Switzerland
** All rights reserved
*/

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http_reader.h"

#if !(defined __APPLE__ && defined __MACH__)
extern int snprintf(char *str, size_t size, char *format, ...);
#endif

static void putlabel (int state) {
	if ((state == HTTP_READER_STATE_READING_METHOD)
		|| (state == HTTP_READER_STATE_COMPLETED_METHOD))
	{
		fputs("method = ", stdout);
	} else if ((state == HTTP_READER_STATE_READING_URI)
		|| (state == HTTP_READER_STATE_COMPLETED_URI))
	{
		fputs("uri = ", stdout);
	} else if ((state == HTTP_READER_STATE_READING_VERSION)
		|| (state == HTTP_READER_STATE_COMPLETED_VERSION))
	{
		fputs("version = ", stdout);
	} else if ((state == HTTP_READER_STATE_READING_STATUS)
		|| (state == HTTP_READER_STATE_COMPLETED_STATUS))
	{
		fputs("status = ", stdout);
	} else if ((state == HTTP_READER_STATE_READING_REASON)
		|| (state == HTTP_READER_STATE_COMPLETED_REASON))
	{
		fputs("reason = ", stdout);
	} else if ((state == HTTP_READER_STATE_READING_HEADER_NAME)
		|| (state == HTTP_READER_STATE_COMPLETED_HEADER_NAME))
	{
		fputs("header-name = ", stdout);
	} else if ((state == HTTP_READER_STATE_READING_HEADER_VALUE)
		|| (state == HTTP_READER_STATE_COMPLETED_HEADER_VALUE))
	{
		fputs("header-value = ", stdout);
	}
}

static void putdata (char* data, size_t length) {
	size_t i;
	assert(data != 0);
	for (i = 0; i != length; i++) {
		fputc(data[i], stdout);
	}
}


static size_t handle_buffer (
	struct http_reader* r, char* buffer, size_t length)
{
	size_t n;
	assert(r != 0);
	assert(buffer != 0);
	n = 0;
	while ((n != length)
			&& (r->state != HTTP_READER_STATE_DONE)
			&& (r->state != HTTP_READER_STATE_ERROR))
	{
		n += http_reader_read(r, &buffer[n], length - n);
		printf("state = %d", r->state);
		if (r->result_token != 0) {
			fputc(',', stdout);
			fputc(' ', stdout);
			putlabel(r->state);
			fputc('\"', stdout);
			putdata(r->result_token, r->result_length);
			fputc('\"', stdout);
		}
		fputc('\n', stdout);
	}
	return n;
}

int main () {
	size_t n;
	int length;
	char buffer[64 * 1024];
	struct http_reader reader;

	length = snprintf(buffer, sizeof buffer,
		"HTTP/1.1 101 \r\n"
		"Upgrade:PTTH/1.0\r\n"
		"Connection:Upgrade\r\n\r\n"
		"CONNECT xyz HTTP/1.1\r\n"
		"Host:try.yaler.net:80\r\n\r\n");
	assert((0 <= length) && ((size_t) length < sizeof buffer));

	n = 0;
	printf("RESPONSE:\n");
	http_reader_init(&reader, HTTP_READER_TYPE_RESPONSE);
	n += handle_buffer(&reader, &buffer[n], length - n);
	printf("REQUEST:\n");
	http_reader_init(&reader, HTTP_READER_TYPE_REQUEST);
	n += handle_buffer(&reader, &buffer[n], length - n);
	exit(EXIT_SUCCESS);
}
