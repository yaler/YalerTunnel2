/*
** Copyright (c) 2013, Yaler GmbH, Switzerland
** All rights reserved
*/

#include <assert.h>

#include "http_reader.h"

#define CR 13
#define LF 10
#define SP 32
#define HT 9

#define SUBSTATE_NONE 0
#define SUBSTATE_READING 1
#define SUBSTATE_AFTER_CR 2
#define SUBSTATE_AFTER_LF 3
#define SUBSTATE_AFTER_SP 4

void http_reader_init (struct http_reader* r, int type) {
	assert(r != 0);
	if (type == HTTP_READER_TYPE_REQUEST) {
		r->type = HTTP_READER_TYPE_REQUEST;
		r->state = HTTP_READER_STATE_EXPECTING_METHOD;
	} else {
		assert(type == HTTP_READER_TYPE_RESPONSE);
		r->type = HTTP_READER_TYPE_RESPONSE;
		r->state = HTTP_READER_STATE_EXPECTING_VERSION;
	}
	r->substate = SUBSTATE_NONE;
	r->in_quoted_pair = 0;
	r->in_quoted_string = 0;
	r->result_token = 0;
	r->result_length = 0;
}

static int is_digit (int c) {
	return ('0' <= c) && (c <= '9');
}

static int is_whitespace (int c) {
	return (c == SP) || (c == HT);
}

static int is_token_char (int c) {
	return (33 <= c) && (c < 127)
		&& (c != '(') && (c != ')') && (c != '<') && (c != '>') && (c != '@')
		&& (c != ',') && (c != ';') && (c != ':') && (c != '\\') && (c != '"')
		&& (c != '/') && (c != '[') && (c != ']') && (c != '?') && (c != '=')
		&& (c != '{') && (c != '}');
}

static int is_uri_char (int c) {
	return (('A' <= c) && (c <= 'Z'))
		|| (('a' <= c) && (c <= 'z'))
		|| (('0' <= c) && (c <= '9'))
		|| (c == '%') || (c == '-') || (c == '.') || (c == '_') || (c == '~')
		|| (c == ':') || (c == '/') || (c == '?') || (c == '#') || (c == '[')
		|| (c == ']') || (c == '@') || (c == '!') || (c == '$') || (c == '&')
		|| (c == '\'')|| (c == '(') || (c == ')') || (c == '*') || (c == '+')
		|| (c == ',') || (c == ';') || (c == '=');
}

static int is_version_char (int c) {
	return (c == 'H') || (c == 'T') || (c == 'P') || (c == '/') || (c == '.')
		|| (('0' <= c) && (c <= '9'));
}

static int is_text_char (int c) {
	return ((32 <= c) && (c < 127)) || ((128 <= c) && (c < 256)) || (c == HT);
}

static size_t skip_whitespace (char* buffer, size_t length) {
	size_t n;
	assert(buffer != 0);
	n = 0;
	while ((n != length) && is_whitespace(buffer[n])) {
		n++;
	}
	return n;
}

static size_t read_octets (
	struct http_reader* r, char* buffer, size_t length, int (*predicate) (int))
{
	size_t n;
	assert(r != 0);
	assert(buffer != 0);
	assert(predicate != 0);
	n = 0;
	while ((n != length) && predicate(buffer[n])) {
		n++;
	}
	r->result_token = buffer;
	r->result_length = n;
	return n;
}

static size_t read_octets_and_quotes (
	struct http_reader* r, char* buffer, size_t length, int (*predicate) (int))
{
	size_t n;
	assert(r != 0);
	assert(buffer != 0);
	assert(predicate != 0);
	n = 0;
	while ((n != length) && (predicate(buffer[n]) || r->in_quoted_pair)) {
		if (r->in_quoted_pair) {
			r->in_quoted_pair = 0;
		} else if (r->in_quoted_string) {
			if (buffer[n] == '\\') {
				r->in_quoted_pair = 1;
			} else if (buffer[n] == '"') {
				r->in_quoted_string = 0;
			}
		} else if (buffer[n] == '"') {
			r->in_quoted_string = 1;
		}
		n++;
	}
	r->result_token = buffer;
	r->result_length = n;
	return n;
}

size_t http_reader_read (struct http_reader* r, char* buffer, size_t length) {
	size_t n;
	assert(r != 0);
	assert(buffer != 0);
	r->result_token = 0;
	r->result_length = 0;
	n = 0;
	if (n != length) {
		do {
			switch (r->state) {
				case HTTP_READER_STATE_EXPECTING_METHOD:
					if (r->substate == SUBSTATE_NONE) {
						n += skip_whitespace(&buffer[n], length - n);
						if (n != length) {
							if (buffer[n] == CR) {
								n++;
								r->substate = SUBSTATE_AFTER_CR;
							} else if (buffer[n] == LF) {
								n++;
							} else {
								r->state = HTTP_READER_STATE_READING_METHOD;
							}
						}
					} else {
						assert(r->substate == SUBSTATE_AFTER_CR);
						if (buffer[n] == LF) {
							n++;
							r->substate = SUBSTATE_NONE;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					}
					break;
				case HTTP_READER_STATE_READING_METHOD:
					if (r->substate == SUBSTATE_NONE) {
						if (is_token_char(buffer[n])) {
							r->substate = SUBSTATE_READING;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_READING);
						n += read_octets(r, &buffer[n], length - n, is_token_char);
						if (n != length) {
							r->state = HTTP_READER_STATE_COMPLETED_METHOD;
							r->substate = SUBSTATE_NONE;
						}
					}
					break;
				case HTTP_READER_STATE_COMPLETED_METHOD:
					r->state = HTTP_READER_STATE_EXPECTING_URI;
					break;
				case HTTP_READER_STATE_EXPECTING_URI:
					if (r->substate == SUBSTATE_NONE) {
						if (is_whitespace(buffer[n])) {
							n++;
							r->substate = SUBSTATE_AFTER_SP;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_AFTER_SP);
						n += skip_whitespace(&buffer[n], length - n);
						if (n != length) {
							r->state = HTTP_READER_STATE_READING_URI;
							r->substate = SUBSTATE_NONE;
						}
					}
					break;
				case HTTP_READER_STATE_READING_URI:
					if (r->substate == SUBSTATE_NONE) {
						if (is_uri_char(buffer[n])) {
							r->substate = SUBSTATE_READING;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_READING);
						n += read_octets(r, &buffer[n], length - n, is_uri_char);
						if (n != length) {
							r->state = HTTP_READER_STATE_COMPLETED_URI;
							r->substate = SUBSTATE_NONE;
						}
					}
					break;
				case HTTP_READER_STATE_COMPLETED_URI:
					r->state = HTTP_READER_STATE_EXPECTING_VERSION;
					break;
				case HTTP_READER_STATE_EXPECTING_VERSION:
					if (r->type == HTTP_READER_TYPE_REQUEST) {
						if (r->substate == SUBSTATE_NONE) {
							if (is_whitespace(buffer[n])) {
								n++;
								r->substate = SUBSTATE_AFTER_SP;
							} else {
								r->state = HTTP_READER_STATE_ERROR;
							}
						} else {
							assert(r->substate == SUBSTATE_AFTER_SP);
							n += skip_whitespace(&buffer[n], length - n);
							if (n != length) {
								r->state = HTTP_READER_STATE_READING_VERSION;
								r->substate = SUBSTATE_NONE;
							}
						}
					} else {
						assert(r->type == HTTP_READER_TYPE_RESPONSE);
						if (r->substate == SUBSTATE_NONE) {
							n += skip_whitespace(&buffer[n], length - n);
							if (n != length) {
								if (buffer[n] == CR) {
									n++;
									r->substate = SUBSTATE_AFTER_CR;
								} else if (buffer[n] == LF) {
									n++;
								} else {
									r->state = HTTP_READER_STATE_READING_VERSION;
								}
							}
						} else {
							assert(r->substate == SUBSTATE_AFTER_CR);
							if (buffer[n] == LF) {
								n++;
								r->substate = SUBSTATE_NONE;
							} else {
								r->state = HTTP_READER_STATE_ERROR;
							}
						}
					}
					break;
				case HTTP_READER_STATE_READING_VERSION:
					if (r->substate == SUBSTATE_NONE) {
						if (is_version_char(buffer[n])) {
							r->substate = SUBSTATE_READING;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_READING);
						n += read_octets(r, &buffer[n], length - n, is_version_char);
						if (n != length) {
							r->state = HTTP_READER_STATE_COMPLETED_VERSION;
							r->substate = SUBSTATE_NONE;
						}
					}
					break;
				case HTTP_READER_STATE_COMPLETED_VERSION:
					if (r->type == HTTP_READER_TYPE_REQUEST) {
						r->state = HTTP_READER_STATE_EXPECTING_HEADER_NAME;
					} else {
						assert(r->type == HTTP_READER_TYPE_RESPONSE);
						r->state = HTTP_READER_STATE_EXPECTING_STATUS;
					}
					break;
				case HTTP_READER_STATE_EXPECTING_STATUS:
					if (r->substate == SUBSTATE_NONE) {
						if (is_whitespace(buffer[n])) {
							n++;
							r->substate = SUBSTATE_AFTER_SP;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_AFTER_SP);
						n += skip_whitespace(&buffer[n], length - n);
						if (n != length) {
							r->state = HTTP_READER_STATE_READING_STATUS;
							r->substate = SUBSTATE_NONE;
						}
					}
					break;
				case HTTP_READER_STATE_READING_STATUS:
					if (r->substate == SUBSTATE_NONE) {
						if (is_digit(buffer[n])) {
							r->substate = SUBSTATE_READING;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_READING);
						n += read_octets(r, &buffer[n], length - n, is_digit);
						if (n != length) {
							r->state = HTTP_READER_STATE_COMPLETED_STATUS;
							r->substate = SUBSTATE_NONE;
						}
					}
					break;
				case HTTP_READER_STATE_COMPLETED_STATUS:
					r->state = HTTP_READER_STATE_EXPECTING_REASON;
					break;
				case HTTP_READER_STATE_EXPECTING_REASON:
					if (r->substate == SUBSTATE_NONE) {
						if (is_whitespace(buffer[n])) {
							n++;
							r->substate = SUBSTATE_AFTER_SP;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_AFTER_SP);
						n += skip_whitespace(&buffer[n], length - n);
						if (n != length) {
							r->state = HTTP_READER_STATE_READING_REASON;
							r->substate = SUBSTATE_NONE;
						}
					}
					break;
				case HTTP_READER_STATE_READING_REASON:
					n += read_octets(r, &buffer[n], length - n, is_text_char);
					if (n != length) {
						r->state = HTTP_READER_STATE_COMPLETED_REASON;
					}
					break;
				case HTTP_READER_STATE_COMPLETED_REASON:
					r->state = HTTP_READER_STATE_EXPECTING_HEADER_NAME;
					break;
				case HTTP_READER_STATE_EXPECTING_HEADER_NAME:
					if (r->substate == SUBSTATE_NONE) {
						if (buffer[n] == CR) {
							n++;
							r->substate = SUBSTATE_AFTER_CR;
						} else if (buffer[n] == LF) {
							n++;
							r->state = HTTP_READER_STATE_READING_HEADER_NAME;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_AFTER_CR);
						if (buffer[n] == LF) {
							n++;
							r->state = HTTP_READER_STATE_READING_HEADER_NAME;
							r->substate = SUBSTATE_NONE;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					}
					break;
				case HTTP_READER_STATE_READING_HEADER_NAME:
					if (r->substate == SUBSTATE_NONE) {
						if (is_token_char(buffer[n])) {
							r->substate = SUBSTATE_READING;
						} else {
							r->state = HTTP_READER_STATE_ENDING_HEADER_LINES;
						}
					} else {
						assert(r->substate == SUBSTATE_READING);
						n += read_octets(r, &buffer[n], length - n, is_token_char);
						if (n != length) {
							r->state = HTTP_READER_STATE_COMPLETED_HEADER_NAME;
							r->substate = SUBSTATE_NONE;
						}
					}
					break;
				case HTTP_READER_STATE_COMPLETED_HEADER_NAME:
					r->state = HTTP_READER_STATE_EXPECTING_HEADER_VALUE;
					break;
				case HTTP_READER_STATE_EXPECTING_HEADER_VALUE:
					if (buffer[n] == ':') {
						n++;
						r->state = HTTP_READER_STATE_READING_HEADER_VALUE;
					} else {
						r->state = HTTP_READER_STATE_ERROR;
					}
					break;
				case HTTP_READER_STATE_READING_HEADER_VALUE:
					n += read_octets_and_quotes(r, &buffer[n], length - n, is_text_char);
					if (n != length) {
						r->state = HTTP_READER_STATE_COMPLETED_HEADER_VALUE;
					}
					break;
				case HTTP_READER_STATE_COMPLETED_HEADER_VALUE:
					r->state = HTTP_READER_STATE_ENDING_HEADER_LINE;
					break;
				case HTTP_READER_STATE_ENDING_HEADER_LINE:
					if (r->substate == SUBSTATE_NONE) {
						if (buffer[n] == CR) {
							n++;
							r->substate = SUBSTATE_AFTER_CR;
						} else if (buffer[n] == LF) {
							n++;
							r->substate = SUBSTATE_AFTER_LF;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else if (r->substate == SUBSTATE_AFTER_CR) {
						if (buffer[n] == LF) {
							n++;
							r->substate = SUBSTATE_AFTER_LF;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_AFTER_LF);
						if (is_whitespace(buffer[n])) {
							r->state = HTTP_READER_STATE_READING_HEADER_VALUE;
							r->substate = SUBSTATE_NONE;
						} else if (r->in_quoted_string) {
							r->state = HTTP_READER_STATE_ERROR;
						} else {
							r->state = HTTP_READER_STATE_READING_HEADER_NAME;
							r->substate = SUBSTATE_NONE;
						}
					}
					break;
				case HTTP_READER_STATE_ENDING_HEADER_LINES:
					if (r->substate == SUBSTATE_NONE) {
						if (buffer[n] == CR) {
							n++;
							r->substate = SUBSTATE_AFTER_CR;
						} else if (buffer[n] == LF) {
							n++;
							r->state = HTTP_READER_STATE_DONE;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					} else {
						assert(r->substate == SUBSTATE_AFTER_CR);
						if (buffer[n] == LF) {
							n++;
							r->state = HTTP_READER_STATE_DONE;
							r->substate = SUBSTATE_NONE;
						} else {
							r->state = HTTP_READER_STATE_ERROR;
						}
					}
					break;
				case HTTP_READER_STATE_DONE:
				case HTTP_READER_STATE_ERROR:
					break;
				default:
					assert(0);
					break;
			}
		} while ((n != length)
			&& (r->state != HTTP_READER_STATE_COMPLETED_METHOD)
			&& (r->state != HTTP_READER_STATE_COMPLETED_URI)
			&& (r->state != HTTP_READER_STATE_COMPLETED_VERSION)
			&& (r->state != HTTP_READER_STATE_COMPLETED_STATUS)
			&& (r->state != HTTP_READER_STATE_COMPLETED_REASON)
			&& (r->state != HTTP_READER_STATE_COMPLETED_HEADER_NAME)
			&& (r->state != HTTP_READER_STATE_COMPLETED_HEADER_VALUE)
			&& (r->state != HTTP_READER_STATE_DONE)
			&& (r->state != HTTP_READER_STATE_ERROR));
	}
	return n;
}
