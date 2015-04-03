/*
** Copyright (c) 2015, Yaler GmbH, Switzerland
** All rights reserved
*/

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wlong-long"
# include <openssl/ssl.h>
#pragma clang diagnostic pop

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-pedantic"
#	include "udns/udns.h"
#pragma GCC diagnostic pop
#pragma clang diagnostic pop

#include "http_reader.h"

#if !(defined __APPLE__ && defined __MACH__)
extern int snprintf(char* str, size_t size, char *format, ...);
#endif

extern int strncasecmp(const char *s1, const char *s2, size_t n);

#if defined __APPLE__ && defined __MACH__
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

#define HT 9
#define SP 32

#define MODE_CLIENT 'c'
#define MODE_SERVER 's'
#define MODE_PROXY 'p'

#define RELAY_SECURITY_TRANSPORT_PASSTHROUGH 1

#define OP_BIND 1
#define OP_ACCEPT 2
#define OP_CONNECT 4
#define OP_READ 8
#define OP_WRITE 16

#define STATE_OPEN 0
#define STATE_WRITING_REQUEST 1
#define STATE_READING_RESPONSE 2
#define STATE_READING_REQUEST 3
#define STATE_WRITING_RESPONSE 4
#define STATE_RELAYING 5
#define STATE_CLOSING 6
#define STATE_CLOSED 7

#define ERROR_CONFIG "error:configuration"
#define ERROR_SYSCALL "error:system call"
#define ERROR_OOM "error:out of memory"
#define ERROR_DNS "error:DNS"
#define ERROR_SSL "error:SSL"

#define WARNING_OPENSSL_VERSION_MISMATCH "warning:OpenSSL version mismatch"

#define INFO_BUILT_WITH "built with"
#define INFO_CLIENT_INITIATED_RENEGOTIATION "client-initiated renegotiation"
#define INFO_CONNECTION_FAILURE "connection failure"
#define INFO_CONNECTION_TIMEOUT "connection timeout"
#define INFO_DNS_FAILURE "DNS failure"
#define INFO_UNEXPECTED_RELAY_RESPONSE "unexpected relay response"
#define INFO_UNEXPECTED_PROXY_RESPONSE "unexpected proxy response"
#define INFO_UNEXPECTED_PROXY_REQUEST "unexpected proxy request"
#define INFO_USING "using"

struct buffer {
	size_t position, limit;
	char *data;
};

struct socket_desc {
	struct socket_desc *next, *peer;
	char *host;
	int port;
	char *domain;
	int fd, ops, state;
	int read_failed, write_failed;
	time_t stamp;
	SSL *ssl;
	int ssl_handshake;
	int ssl_handshake_count;
	int ssl_handshake_stash;
	struct http_reader http_reader;
	size_t http_reader_position;
	char *http_method;
	size_t http_method_length;
	char *http_status;
	size_t http_status_length;
	char *http_location;
	size_t http_location_length;
	char *http_header_name;
	size_t http_header_name_length;
	char *http_header_value;
	size_t http_header_value_length;
	struct buffer buffer;
};

static int mode;

static int localssl;
static char *localhost;
static int localport;

static int yalerssl;
static char *yalerhost;
static int yalerport;
static char *yalerdomain;

static int min_listeners = 1;
static int max_sockets = INT_MAX;
static int buffer_size = 65536;
static int relay_security = 0;
static time_t max_idle_time = 75;

static time_t now;
static SSL_CTX *ssl_client_ctx = 0;
static SSL_SESSION *yaler_ssl_session = 0;
static SSL_SESSION *local_ssl_session = 0;
static struct socket_desc *sockets = 0;
static int socket_count = 0;
static int listener_count = 0;

static void open_socket (
	char* host, int port, char* domain, struct socket_desc* peer);

static int contains (int set, int bits) {
	return (set & bits) == bits;
}

static void include (int* set, int bits) {
	assert(set != 0);
	*set |= bits;
}

static void exclude (int* set, int bits) {
	assert(set != 0);
	*set &= ~bits;
}

static void clear_buffer (struct buffer* b) {
	assert(buffer_size >= 0);
	assert(b != 0);
	b->position = 0;
	b->limit = buffer_size;
}

static void flip_buffer (struct buffer* b) {
	assert(b != 0);
	b->limit = b->position;
	b->position = 0;
}

static void compact_buffer (struct buffer* b) {
	assert(b != 0);
	assert(b->data != 0);
	assert(b->position <= b->limit);
	assert(b->limit <= (size_t) buffer_size);
	memmove(b->data, &b->data[b->position], b->limit - b->position);
	b->position = b->limit - b->position;
	b->limit = buffer_size;
}

static char* ssl_error_msg (int ssl_error) {
	char *msg;
	switch (ssl_error) {
		case SSL_ERROR_NONE:
			msg = "SSL_ERROR_NONE";
			break;
		case SSL_ERROR_ZERO_RETURN:
			msg = "SSL_ERROR_ZERO_RETURN";
			break;
		case SSL_ERROR_WANT_READ:
			msg = "SSL_ERROR_WANT_READ";
			break;
		case SSL_ERROR_WANT_WRITE:
			msg = "SSL_ERROR_WANT_WRITE";
			break;
		case SSL_ERROR_WANT_CONNECT:
			msg = "SSL_ERROR_WANT_CONNECT";
			break;
		case SSL_ERROR_WANT_ACCEPT:
			msg = "SSL_ERROR_WANT_ACCEPT";
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			msg = "SSL_ERROR_WANT_X509_LOOKUP";
			break;
		case SSL_ERROR_SYSCALL:
			msg = "SSL_ERROR_SYSCALL";
			break;
		case SSL_ERROR_SSL:
			msg = "SSL_ERROR_SSL";
			break;
		default:
			msg = "";
			break;
	}
	return msg;
}

static void eprintf (char* format, ...) {
	time_t t; struct tm *gmt; va_list args;
	assert(format != 0);
	t = time(0);
	if (t == (time_t) -1) {
		t = 0;
	}
	gmt = gmtime(&t);
	fprintf(stderr, "%04d-%02d-%02d'T'%02d:%02d:%02d'Z':",
		1900 + gmt->tm_year, 1 + gmt->tm_mon, gmt->tm_mday,
		gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

static void eprintf_buffer (struct buffer* b) {
	size_t i, j;
	assert(b != 0);
	assert(b->data != 0);
	i = 0; j = b->position;
	while (i != j) {
		if ((i == 0) || (b->data[i - 1] == '\n')) {
			fputc('\t', stderr);
		}
		fputc(b->data[i], stderr);
		i++;
	}
	if ((i == 0) || (b->data[i - 1] != '\n')) {
		fputc('\n', stderr);
	}
}

static void log_error (char* msg, int error, char* file, int line) {
	assert(msg != 0);
	assert(file != 0);
	eprintf("%s:%d:%s@%s:%d\n", msg, error, strerror(error), file, line);
}

static void log_dns_error (char* msg, char* host,
	int dns_error, char* file, int line)
{
	assert(msg != 0);
	assert(file != 0);
	eprintf("%s:%d:%s:%s@%s:%d\n",
		msg, dns_error, dns_strerror(dns_error), host, file, line);
}

static void log_ssl_error (char* msg, int ssl_error, char* file, int line) {
	assert(msg != 0);
	assert(file != 0);
	if ((ssl_error == SSL_ERROR_SYSCALL) && (errno != 0)) {
		eprintf("%s:%d:%s:@%s:%d\n",
			msg, errno, strerror(errno), file, line);
	} else {
		eprintf("%s:%d:%s@%s:%d\n",
			msg, ssl_error, ssl_error_msg(ssl_error), file, line);
	}
}

static void log_socket_error (char* msg, char* host, int port,
	int error, char* file, int line)
{
	assert(msg != 0);
	assert(host != 0);
	assert(file != 0);
	eprintf("%s:%d:%s:%s:%d@%s:%d\n",
		msg, error, strerror(error), host, port, file, line);
}

static void log_ssl_socket_error (char* msg, char* host, int port,
	int ssl_error, char* file, int line)
{
	assert(msg != 0);
	assert(host != 0);
	assert(file != 0);
	if ((ssl_error == SSL_ERROR_SYSCALL) && (errno != 0)) {
		eprintf("%s:%d:%s:%s:%d@%s:%d\n",
			msg, errno, strerror(errno), host, port, file, line);
	} else {
		eprintf("%s:%d:%s:%s:%d@%s:%d\n",
			msg, ssl_error, ssl_error_msg(ssl_error), host, port, file, line);
	}
}

static void log_protocol_error (char* msg, char* host, int port,
	struct buffer* buffer, char* file, int line)
{
	assert(msg != 0);
	assert(host != 0);
	assert(buffer != 0);
	assert(file != 0);
	eprintf("%s:%s:%d:%d@%s:%d\n", msg, host, port, buffer->position, file, line);
	eprintf_buffer(buffer);
}

static void set_nonblocking (int fd) {
	int r;
	r = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (r == -1) {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void set_reuseaddr (int fd) {
	int r, v;
	v = 1;
	r = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v);
	if (r == -1) {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void set_nodelay (int fd) {
	int r, v;
	v = 1;
	r = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof v);
	if (r == -1) {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void init_dns (int *fd) {
	int r;
	assert(fd != 0);
	*fd = dns_init(0, 1);
	if (*fd >= 0) {
		r = dns_set_opts(0, "udpbuf:512");
		if (r != 0) {
			eprintf("%s:%s@%s:%d\n", ERROR_DNS, "dns_init", __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void check_openssl_version () {
	long v;
	v = SSLeay();
	if (v != OPENSSL_VERSION_NUMBER) {
		eprintf("%s:%s: %lx, %s: %lx\n", WARNING_OPENSSL_VERSION_MISMATCH,
			INFO_BUILT_WITH, OPENSSL_VERSION_NUMBER, INFO_USING, v);
	}
}

static void update_ssl_session (SSL* ssl, SSL_SESSION** session) {
	assert(ssl != 0);
	assert(session != 0);
	if (!SSL_session_reused(ssl)) {
		if (*session != 0) {
			SSL_SESSION_free(*session);
		}
		*session = SSL_get1_session(ssl);
	}
}

static void handle_ssl_info (const SSL* ssl, int where, int r) {
	struct socket_desc* s; (void) r;
	if ((where & SSL_CB_HANDSHAKE_START) == SSL_CB_HANDSHAKE_START) {
		s = (struct socket_desc*) SSL_get_app_data(ssl);
		assert(s != 0);
		if (s->ssl_handshake_count != INT_MAX) {
			s->ssl_handshake_count++;
		}
	}
}

static void init_ssl_client_ctx (SSL_CTX** c) {
	assert(c != 0);
	SSL_library_init();
	SSL_load_error_strings();
	*c = SSL_CTX_new(SSLv23_client_method());
	if (*c == 0) {
		log_ssl_error(ERROR_SSL, SSL_ERROR_SSL, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_options(*c, SSL_OP_ALL | SSL_OP_NO_SSLv2
		| SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
	SSL_CTX_set_info_callback(*c, handle_ssl_info);
}

static void register_socket (struct socket_desc* s) {
	assert(socket_count < max_sockets);
	assert(s != 0);
	s->next = sockets;
	sockets = s;
	socket_count++;
}

static void close_socket (struct socket_desc* s) {
	assert(socket_count > 0);
	assert(s != 0);
	assert(s->state != STATE_CLOSED);
	if (s->ssl != 0) {
		SSL_set_shutdown(s->ssl, SSL_SENT_SHUTDOWN);
		SSL_free(s->ssl);
		s->ssl = 0;
	}
	if (s->fd != -1) {
		shutdown(s->fd, SHUT_RDWR);
		close(s->fd);
		s->fd = -1;
	}
	s->ops = 0;
	s->state = STATE_CLOSED;
	socket_count--;
}

static void shutdown_ssl (struct socket_desc* s) {
	int r;
	assert(s != 0);
	assert(s->ssl != 0);
	r = SSL_shutdown(s->ssl);
	if (r == -1) {
		r = SSL_get_error(s->ssl, r);
		if (r == SSL_ERROR_WANT_WRITE) {
			s->ops = OP_WRITE;
			s->state = STATE_CLOSING;
		} else {
			close_socket(s);
		}
	} else {
		assert((r == 1) || (r == 0));
		close_socket(s);
	}
}

static void prepare_ssl_handshake (struct socket_desc* s) {
	assert(s != 0);
	assert(!s->ssl_handshake);
	s->ssl_handshake = 1;
	s->ssl_handshake_stash = s->ops;
	if (s->peer != 0) {
		s->peer->ssl_handshake_stash = s->peer->ops;
		s->peer->ops = 0;
	}
}

static void prepare_writing_request (struct socket_desc* s) {
	int r; char* request;
	assert(buffer_size >= 0);
	assert(s != 0);
	assert(s->host != 0);
	assert(s->domain != 0);
	assert(s->buffer.data != 0);
	s->state = STATE_WRITING_REQUEST;
	if (mode == MODE_CLIENT) {
		request =
			"CONNECT /%s HTTP/1.1\r\n"
			"Host: %s:%d\r\n\r\n";
	} else {
		assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
		if (relay_security == 0) {
			request =
				"POST /%s HTTP/1.1\r\n"
				"Upgrade: PTTH/1.0\r\n"
				"Connection: Upgrade\r\n"
				"Host: %s:%d\r\n\r\n";
		} else if (relay_security == RELAY_SECURITY_TRANSPORT_PASSTHROUGH) {
			request =
				"POST /%s HTTP/1.1\r\n"
				"Upgrade: PTTH/1.0\r\n"
				"Connection: Upgrade\r\n"
				"Host: %s:%d\r\n"
				"X-Relay-Security: transport/pass-through\r\n\r\n";
		} else {
			assert(0);
		}
	}
	r = snprintf(s->buffer.data, buffer_size,
		request, s->domain, s->host, s->port);
	if ((0 <= r) || (r < buffer_size)) {
		s->buffer.limit = r;
		s->buffer.position = 0;
	} else {
		eprintf("%s@%s:%d\n", ERROR_CONFIG, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void prepare_reading_response (struct socket_desc* s) {
	assert(s != 0);
	s->state = STATE_READING_RESPONSE;
	http_reader_init(&s->http_reader, HTTP_READER_TYPE_RESPONSE);
	s->http_reader_position = 0;
	s->http_status = 0;
	s->http_location = 0;
	s->http_header_name = 0;
	s->http_header_value = 0;
}

static void prepare_reading_request (struct socket_desc* s) {
	assert(s != 0);
	s->state = STATE_READING_REQUEST;
	http_reader_init(&s->http_reader, HTTP_READER_TYPE_REQUEST);
	s->http_reader_position = 0;
	s->http_method = 0;
	s->http_header_name = 0;
	s->http_header_value = 0;
}

static void prepare_writing_response (struct socket_desc* s) {
	int r;
	assert(buffer_size >= 0);
	assert(s != 0);
	assert(s->buffer.data != 0);
	s->state = STATE_WRITING_RESPONSE;
	r = snprintf(s->buffer.data, buffer_size, "HTTP/1.1 200 OK\r\n\r\n");
	if ((0 <= r) || (r < buffer_size)) {
		s->buffer.limit = r;
		s->buffer.position = 0;
	} else {
		eprintf("%s@%s:%d\n", ERROR_CONFIG, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void prepare_relaying (struct socket_desc* s) {
	assert(s != 0);
	assert(s->peer != 0);
	s->state = STATE_RELAYING;
	s->peer->state = STATE_RELAYING;
}

static void begin_relaying (struct socket_desc* s) {
	assert(s != 0);
	assert(s->peer != 0);
	s->ops = 0;
	s->peer->ops = 0;
	if (s->buffer.position == 0) {
		include(&s->ops, OP_READ);
	} else {
		flip_buffer(&s->buffer);
		include(&s->peer->ops, OP_WRITE);
	}
	if (s->peer->buffer.position == 0) {
		include(&s->peer->ops, OP_READ);
	} else {
		flip_buffer(&s->peer->buffer);
		include(&s->ops, OP_WRITE);
	}
}

static void update_token (struct http_reader* r, char** token, size_t* length) {
	assert(r != 0);
	assert(token != 0);
	assert(length != 0);
	if (*token == 0) {
		*token = r->result_token;
		*length = r->result_length;
	} else if (r->result_token != 0) {
		assert(&(*token)[*length] == r->result_token);
		*length += r->result_length;
	}
}

static void handle_http (struct socket_desc* s) {
	struct http_reader *r;
	assert(s != 0);
	assert(s->buffer.data != 0);
	assert(s->http_reader_position <= s->buffer.position);
	r = &s->http_reader;
	do {
		s->http_reader_position += http_reader_read(r,
			&s->buffer.data[s->http_reader_position],
			s->buffer.position - s->http_reader_position);
		switch (r->state) {
			case HTTP_READER_STATE_READING_METHOD:
			case HTTP_READER_STATE_COMPLETED_METHOD:
				update_token(r, &s->http_method, &s->http_method_length);
				break;
			case HTTP_READER_STATE_READING_STATUS:
			case HTTP_READER_STATE_COMPLETED_STATUS:
				update_token(r, &s->http_status, &s->http_status_length);
				break;
			case HTTP_READER_STATE_READING_HEADER_NAME:
			case HTTP_READER_STATE_COMPLETED_HEADER_NAME:
				update_token(r, &s->http_header_name, &s->http_header_name_length);
				break;
			case HTTP_READER_STATE_READING_HEADER_VALUE:
				update_token(r, &s->http_header_value, &s->http_header_value_length);
				break;
			case HTTP_READER_STATE_COMPLETED_HEADER_VALUE:
				update_token(r, &s->http_header_value, &s->http_header_value_length);
				if (s->state == STATE_READING_RESPONSE) {
					assert(s->http_header_name != 0);
					if ((s->http_header_name_length == 8)
						&& (strncasecmp(s->http_header_name, "Location", 8) == 0))
					{
						if (s->http_location == 0) {
							s->http_location = s->http_header_value;
							s->http_location_length = s->http_header_value_length;
						} else {
							log_protocol_error(INFO_UNEXPECTED_RELAY_RESPONSE,
								s->host, s->port, &s->buffer, __FILE__, __LINE__);
							exit(EXIT_FAILURE);
						}
					}
				}
				s->http_header_name = 0;
				s->http_header_value = 0;
				break;
		}
	} while ((s->http_reader_position != s->buffer.position)
		&& (r->state != HTTP_READER_STATE_DONE)
		&& (r->state != HTTP_READER_STATE_ERROR));
}

static void handle_switch (struct socket_desc* s) {
	assert(s != 0);
	open_socket(yalerhost, yalerport, yalerdomain, 0);
	if (mode == MODE_SERVER) {
		s->ops = 0;
		s->state = STATE_OPEN;
		open_socket(localhost, localport, 0, s);
	} else {
		assert(mode == MODE_PROXY);
		prepare_reading_request(s);
		s->ops = OP_READ;
		handle_http(s);
		if (s->http_reader.state == HTTP_READER_STATE_DONE) {
			assert(s->http_method != 0);
			if ((s->http_method_length == 7)
				&& (strncmp(s->http_method, "CONNECT", 7) == 0)
				&& (s->http_reader_position == s->buffer.position))
			{
				prepare_writing_response(s);
				s->ops = OP_WRITE;
			} else {
				log_protocol_error(INFO_UNEXPECTED_PROXY_REQUEST,
					s->host, s->port, &s->buffer, __FILE__, __LINE__);
				assert(s->peer == 0);
				close_socket(s);
			}
		} else if ((s->http_reader.state == HTTP_READER_STATE_ERROR)
		 || (s->buffer.position == s->buffer.limit))
		{
			log_protocol_error(INFO_UNEXPECTED_PROXY_REQUEST,
				s->host, s->port, &s->buffer, __FILE__, __LINE__);
			assert(s->peer == 0);
			close_socket(s);
		}
	}
}

static void handle_redirect (struct socket_desc* s) {
	size_t i, j, hpos, hlen, dpos, dlen;
	char *host, *domain;
	int port;
	assert(s != 0);
	if (s->http_location != 0) {
		i = 0; j = s->http_location_length;
		while ((i != j) && ((i == 0)
			|| (s->http_location[i] != '/') || (s->http_location[i - 1] != '/')))
		{
			i++;
		}
		if (i != j) {
			i++;
			hpos = i;
			while ((i != j)
				&& (s->http_location[i] != ':') && (s->http_location[i] != '/'))
			{
				i++;
			}
			hlen = i - hpos;
			if ((i != j) && (s->http_location[i] == ':')) {
				i++;
				port = 0;
				while ((i != j)
					&& ('0' <= s->http_location[i]) && (s->http_location[i] <= '9'))
				{
					port = 10 * port + s->http_location[i] - '0';
					i++;
				}
			} else {
				port = 80;
			}
			if ((i != j) && (s->http_location[i] == '/')) {
				i++;
				dpos = i;
				while ((i != j)
					&& (s->http_location[i] != SP) && (s->http_location[i] != HT))
				{
					i++;
				}
				dlen = i - dpos;
				if (s->ssl != 0) {
					shutdown_ssl(s);
				} else {
					close_socket(s);
				}
				if (s->host != yalerhost) {
					assert(s->host != 0);
					assert(s->host != localhost);
					free(s->host);
				}
				host = (char*) malloc(hlen + 1);
				if (host != 0) {
					memcpy(host, &s->http_location[hpos], hlen);
					host[hlen] = 0;
					if (s->domain != yalerdomain) {
						assert(s->domain != 0);
						free(s->domain);
					}
					domain = (char*) malloc(dlen + 1);
					if (domain != 0) {
						memcpy(domain, &s->http_location[dpos], dlen);
						domain[dlen] = 0;
						open_socket(host, port, domain, s->peer);
					} else {
						eprintf("%s@%s:%d\n", ERROR_OOM, __FILE__, __LINE__);
						exit(EXIT_FAILURE);
					}
				} else {
					eprintf("%s@%s:%d\n", ERROR_OOM, __FILE__, __LINE__);
					exit(EXIT_FAILURE);
				}
			} else {
				log_protocol_error(INFO_UNEXPECTED_RELAY_RESPONSE,
					s->host, s->port, &s->buffer, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		} else {
			log_protocol_error(INFO_UNEXPECTED_RELAY_RESPONSE,
				s->host, s->port, &s->buffer, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		log_protocol_error(INFO_UNEXPECTED_RELAY_RESPONSE,
			s->host, s->port, &s->buffer, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void handle_buffer (struct socket_desc* s) {
	assert(s != 0);
	handle_http(s);
	if (s->http_reader.state == HTTP_READER_STATE_DONE) {
		if (s->state == STATE_READING_RESPONSE) {
			assert(s->http_status != 0);
			if (s->http_status_length == 3) {
				if (strncmp(s->http_status, "307", 3) == 0) {
					handle_redirect(s);
				} else {
					if (mode == MODE_CLIENT) {
						if (strncmp(s->http_status, "200", 3) == 0) {
							s->buffer.limit = s->buffer.position;
							s->buffer.position = s->http_reader_position;
							compact_buffer(&s->buffer);
							prepare_relaying(s);
							begin_relaying(s);
						} else {
							log_protocol_error(INFO_UNEXPECTED_PROXY_RESPONSE,
								s->host, s->port, &s->buffer, __FILE__, __LINE__);
							if (strncmp(s->http_status, "504", 3) == 0) {
								if (s->peer->ssl != 0) {
									shutdown_ssl(s->peer);
								} else {
									close_socket(s->peer);
								}
								if (s->ssl != 0) {
									shutdown_ssl(s);
								} else {
									close_socket(s);
								}
							} else {
								exit(EXIT_FAILURE);
							}
						}
					} else {
						assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
						if (strncmp(s->http_status, "101", 3) == 0) {
							s->buffer.limit = s->buffer.position;
							s->buffer.position = s->http_reader_position;
							compact_buffer(&s->buffer);
							handle_switch(s);
						} else if ((strncmp(s->http_status, "204", 3) == 0)
							&& (s->http_reader_position == s->buffer.position))
						{
							prepare_writing_request(s);
							s->ops = OP_WRITE;
						} else {
							log_protocol_error(INFO_UNEXPECTED_RELAY_RESPONSE,
								s->host, s->port, &s->buffer, __FILE__, __LINE__);
							exit(EXIT_FAILURE);
						}
					}
				}
			} else {
				log_protocol_error(INFO_UNEXPECTED_RELAY_RESPONSE,
					s->host, s->port, &s->buffer, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		} else {
			assert((s->state == STATE_READING_REQUEST) && (mode == MODE_PROXY));
			assert(s->http_method != 0);
			if ((s->http_method_length == 7)
				&& (strncmp(s->http_method, "CONNECT", 7) == 0)
				&& (s->http_reader_position == s->buffer.position))
			{
				prepare_writing_response(s);
				s->ops = OP_WRITE;
			} else {
				log_protocol_error(INFO_UNEXPECTED_PROXY_REQUEST,
					s->host, s->port, &s->buffer, __FILE__, __LINE__);
				assert(s->peer == 0);
				close_socket(s);
			}
		}
	} else if ((s->http_reader.state == HTTP_READER_STATE_ERROR)
		|| (s->buffer.position == s->buffer.limit))
	{
		if (s->state == STATE_READING_RESPONSE) {
			log_protocol_error(INFO_UNEXPECTED_RELAY_RESPONSE,
				s->host, s->port, &s->buffer, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		} else {
			assert((s->state == STATE_READING_REQUEST) && (mode == MODE_PROXY));
			log_protocol_error(INFO_UNEXPECTED_PROXY_REQUEST,
				s->host, s->port, &s->buffer, __FILE__, __LINE__);
			assert(s->peer == 0);
			close_socket(s);
		}
	}
}

static void read_socket (struct socket_desc* s) {
	ssize_t n; struct buffer *b;
	assert(s != 0);
	b = &s->buffer;
	assert(b->data != 0);
	assert(b->position <= b->limit);
	do {
		n = recv(s->fd, &b->data[b->position], b->limit - b->position, 0);
	} while ((n == -1) && (errno == EINTR));
	if (n > 0) {
		b->position += n;
		if ((s->state == STATE_READING_RESPONSE)
			|| (s->state == STATE_READING_REQUEST))
		{
			handle_buffer(s);
		} else {
			assert(s->state == STATE_RELAYING);
			assert(s->peer != 0);
			flip_buffer(b);
			exclude(&s->ops, OP_READ);
			include(&s->peer->ops, OP_WRITE);
		}
	} else if ((n == 0) ||
		((n == -1) && (errno != EAGAIN) && (errno != EWOULDBLOCK)))
	{
		if ((s->state == STATE_READING_RESPONSE)
			|| (s->state == STATE_READING_REQUEST))
		{
			log_socket_error(INFO_CONNECTION_FAILURE,
				s->host, s->port, errno, __FILE__, __LINE__);
			if (mode == MODE_CLIENT) {
				assert(s->peer != 0);
				if (s->peer->ssl != 0) {
					shutdown_ssl(s->peer);
				} else {
					close_socket(s->peer);
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
				assert(s->peer == 0);
				if (s->state == STATE_READING_RESPONSE) {
					assert(listener_count > 0);
					listener_count--;
				}
			}
			close_socket(s);
		} else {
			assert(s->state == STATE_RELAYING);
			assert(s->peer != 0);
			if (!s->write_failed && !s->peer->read_failed) {
				if (s->peer->ssl != 0) {
					shutdown_ssl(s->peer);
					close_socket(s);
				} else {
					shutdown(s->peer->fd, SHUT_WR);
					exclude(&s->ops, OP_READ);
					s->read_failed = 1;
				}
			} else {
				if ((s->peer->ssl != 0) && !s->peer->read_failed) {
					shutdown_ssl(s->peer);
				} else {
					close_socket(s->peer);
				}
				close_socket(s);
			}
		}
	}
}

static void read_ssl_socket (struct socket_desc* s) {
	int r; struct buffer *b;
	assert(s != 0);
	assert(s->ssl != 0);
	assert(!s->ssl_handshake);
	b = &s->buffer;
	assert(b->data != 0);
	assert(b->position <= b->limit);
	r = SSL_read(s->ssl, &b->data[b->position], b->limit - b->position);
	if ((s->ssl_handshake_count > 1) &&
		(mode == MODE_CLIENT) && (s->host == localhost) && (s->port == localport))
	{
		assert(s->peer != 0);
		log_ssl_socket_error(INFO_CLIENT_INITIATED_RENEGOTIATION,
			s->host, s->port, SSL_ERROR_SSL, __FILE__, __LINE__);
		if ((s->peer->ssl != 0) && !s->peer->read_failed) {
			shutdown_ssl(s->peer);
		} else {
			close_socket(s->peer);
		}
		close_socket(s);
	} else if (r > 0) {
		b->position += r;
		if ((s->state == STATE_READING_RESPONSE)
			|| (s->state == STATE_READING_REQUEST))
		{
			handle_buffer(s);
		} else {
			assert(s->state == STATE_RELAYING);
			assert(s->peer != 0);
			flip_buffer(b);
			exclude(&s->ops, OP_READ);
			include(&s->peer->ops, OP_WRITE);
		}
	} else {
		r = SSL_get_error(s->ssl, r);
		if (r == SSL_ERROR_WANT_WRITE) {
			prepare_ssl_handshake(s);
			s->ops = OP_WRITE;
		} else if (r != SSL_ERROR_WANT_READ) {
			if ((s->state == STATE_READING_RESPONSE)
				|| (s->state == STATE_READING_REQUEST))
			{
				log_ssl_socket_error(INFO_CONNECTION_FAILURE,
					s->host, s->port, r, __FILE__, __LINE__);
				if (mode == MODE_CLIENT) {
					assert(s->peer != 0);
					if (s->peer->ssl != 0) {
						shutdown_ssl(s->peer);
					} else {
						close_socket(s->peer);
					}
				} else {
					assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
					assert(s->peer == 0);
					if (s->state == STATE_READING_RESPONSE) {
						assert(listener_count > 0);
						listener_count--;
					}
				}
				close_socket(s);
			} else {
				assert(s->state == STATE_RELAYING);
				assert(s->peer != 0);
				if (!s->write_failed && !s->peer->read_failed) {
					if (s->peer->ssl != 0) {
						shutdown_ssl(s->peer);
						close_socket(s);
					} else {
						shutdown(s->peer->fd, SHUT_WR);
						exclude(&s->ops, OP_READ);
						s->read_failed = 1;
					}
				} else {
					if ((s->peer->ssl != 0) && !s->peer->read_failed) {
						shutdown_ssl(s->peer);
					} else {
						close_socket(s->peer);
					}
					close_socket(s);
				}
			}
		}
	}
}

static void write_socket (struct socket_desc* s) {
	ssize_t n; struct buffer *b;
	assert(s != 0);
	if ((s->state == STATE_WRITING_REQUEST)
		|| (s->state == STATE_WRITING_RESPONSE))
	{
		b = &s->buffer;
	} else {
		assert(s->state == STATE_RELAYING);
		assert(s->peer != 0);
		b = &s->peer->buffer;
	}
	assert(b->data != 0);
	assert(b->position <= b->limit);
	do {
		n = send(s->fd, &b->data[b->position], b->limit - b->position,
			MSG_NOSIGNAL);
	} while ((n == -1) && (errno == EINTR));
	if (n > 0) {
		b->position += n;
		if (b->position == b->limit) {
			clear_buffer(b);
			if (s->state == STATE_WRITING_REQUEST) {
				prepare_reading_response(s);
				s->ops = OP_READ;
			} else if (s->state == STATE_WRITING_RESPONSE) {
				assert(mode == MODE_PROXY);
				s->ops = 0;
				s->state = STATE_OPEN;
				open_socket(localhost, localport, 0, s);
			} else {
				assert(s->state == STATE_RELAYING);
				assert(s->peer != 0);
				assert(s->peer->state == STATE_RELAYING);
				exclude(&s->ops, OP_WRITE);
				include(&s->peer->ops, OP_READ);
			}
		}
	} else if ((n == 0) ||
		((n == -1) && (errno != EAGAIN) && (errno != EWOULDBLOCK)))
	{
		if ((s->state == STATE_WRITING_REQUEST)
			|| (s->state == STATE_WRITING_RESPONSE))
		{
			log_socket_error(INFO_CONNECTION_FAILURE,
				s->host, s->port, errno, __FILE__, __LINE__);
			if (mode == MODE_CLIENT) {
				assert(s->peer != 0);
				if (s->peer->ssl != 0) {
					shutdown_ssl(s->peer);
				} else {
					close_socket(s->peer);
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
				assert(s->peer == 0);
				if (s->state == STATE_WRITING_REQUEST) {
					assert(listener_count > 0);
					listener_count--;
				}
			}
			close_socket(s);
		} else {
			assert(s->state == STATE_RELAYING);
			assert(s->peer != 0);
			if (!s->read_failed && !s->peer->write_failed) {
				if (s->peer->ssl == 0) {
					shutdown(s->peer->fd, SHUT_RD);
				}
				exclude(&s->ops, OP_WRITE);
				s->write_failed = 1;
			} else {
				if ((s->peer->ssl != 0) && !s->peer->write_failed) {
					shutdown_ssl(s->peer);
				} else {
					close_socket(s->peer);
				}
				close_socket(s);
			}
		}
	}
}

static void write_ssl_socket (struct socket_desc* s) {
	int r; struct buffer *b;
	assert(s != 0);
	assert(s->ssl != 0);
	assert(!s->ssl_handshake);
	if ((s->state == STATE_WRITING_REQUEST)
		|| (s->state == STATE_WRITING_RESPONSE))
	{
		b = &s->buffer;
	} else {
		assert(s->state == STATE_RELAYING);
		assert(s->peer != 0);
		b = &s->peer->buffer;
	}
	assert(b->data != 0);
	assert(b->position <= b->limit);
	r = SSL_write(s->ssl, &b->data[b->position], b->limit - b->position);
	if ((s->ssl_handshake_count > 1) &&
		(mode == MODE_CLIENT) && (s->host == localhost) && (s->port == localport))
	{
		assert(s->peer != 0);
		log_ssl_socket_error(INFO_CLIENT_INITIATED_RENEGOTIATION,
			s->host, s->port, SSL_ERROR_SSL, __FILE__, __LINE__);
		if ((s->peer->ssl != 0) && !s->peer->write_failed) {
			shutdown_ssl(s->peer);
		} else {
			close_socket(s->peer);
		}
		close_socket(s);
	} else if (r > 0) {
		b->position += r;
		if (b->position == b->limit) {
			clear_buffer(b);
			if (s->state == STATE_WRITING_REQUEST) {
				prepare_reading_response(s);
				s->ops = OP_READ;
			} else if (s->state == STATE_WRITING_RESPONSE) {
				assert(mode == MODE_PROXY);
				s->ops = 0;
				s->state = STATE_OPEN;
				open_socket(localhost, localport, 0, s);
			} else {
				assert(s->state == STATE_RELAYING);
				assert(s->peer != 0);
				assert(s->peer->state == STATE_RELAYING);
				exclude(&s->ops, OP_WRITE);
				include(&s->peer->ops, OP_READ);
			}
		}
	} else {
		r = SSL_get_error(s->ssl, r);
		if (r == SSL_ERROR_WANT_READ) {
			prepare_ssl_handshake(s);
			s->ops = OP_READ;
		} else if (r != SSL_ERROR_WANT_WRITE) {
			if ((s->state == STATE_WRITING_REQUEST)
				|| (s->state == STATE_WRITING_RESPONSE))
			{
				log_ssl_socket_error(INFO_CONNECTION_FAILURE,
					s->host, s->port, r, __FILE__, __LINE__);
				if (mode == MODE_CLIENT) {
					assert(s->peer != 0);
					if (s->peer->ssl != 0) {
						shutdown_ssl(s->peer);
					} else {
						close_socket(s->peer);
					}
				} else {
					assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
					assert(s->peer == 0);
					if (s->state == STATE_WRITING_REQUEST) {
						assert(listener_count > 0);
						listener_count--;
					}
				}
				close_socket(s);
			} else {
				assert(s->state == STATE_RELAYING);
				assert(s->peer != 0);
				if (!s->read_failed && !s->peer->write_failed) {
					if (s->peer->ssl == 0) {
						shutdown(s->peer->fd, SHUT_RD);
					}
					exclude(&s->ops, OP_WRITE);
					s->write_failed = 1;
				} else {
					if ((s->peer->ssl != 0) && !s->peer->write_failed) {
						shutdown_ssl(s->peer);
					} else {
						close_socket(s->peer);
					}
					close_socket(s);
				}
			}
		}
	}
}

static void do_ssl_handshake (struct socket_desc* s) {
	int r;
	assert(s != 0);
	assert(s->ssl != 0);
	assert(s->ssl_handshake);
	r = SSL_do_handshake(s->ssl);
	if (r == 1) {
		if (s->ssl->s3 != 0) {
			s->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
		}
		if (mode == MODE_CLIENT) {
			update_ssl_session(s->ssl, &yaler_ssl_session);
		} else {
			assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
			if (s->peer == 0) {
				update_ssl_session(s->ssl, &yaler_ssl_session);
			} else {
				update_ssl_session(s->ssl, &local_ssl_session);
			}
		}
		if (s->peer != 0) {
			s->peer->ops = s->peer->ssl_handshake_stash;
		}
		s->ops = s->ssl_handshake_stash;
		s->ssl_handshake = 0;
	} else {
		assert(r <= 0);
		r = SSL_get_error(s->ssl, r);
		if (r == SSL_ERROR_WANT_READ) {
			s->ops = OP_READ;
		} else if (r == SSL_ERROR_WANT_WRITE) {
			s->ops = OP_WRITE;
		} else {
			if (r == SSL_ERROR_ZERO_RETURN) {
				log_ssl_socket_error(INFO_CONNECTION_FAILURE,
					s->host, s->port, r, __FILE__, __LINE__);
			} else {
				log_ssl_error(ERROR_SSL, r, __FILE__, __LINE__);
			}
			if (s->peer != 0) {
				if (s->peer->ssl != 0) {
					shutdown_ssl(s->peer);
				} else {
					close_socket(s->peer);
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
				if ((s->state == STATE_WRITING_REQUEST)
					|| (s->state == STATE_READING_RESPONSE))
				{
					assert(listener_count > 0);
					listener_count--;
				}
			}
			close_socket(s);
		}
	}
}

static void init_ssl_client (struct socket_desc* s, SSL_SESSION* session) {
	int r;
	assert(s != 0);
	assert(s->ssl == 0);
	s->ssl = SSL_new(ssl_client_ctx);
	if (s->ssl == 0) {
		log_ssl_error(ERROR_SSL, SSL_ERROR_SSL, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	SSL_set_mode(s->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_set_connect_state(s->ssl);
	r = SSL_set_fd(s->ssl, s->fd);
	if (r == 0) {
		log_ssl_error(ERROR_SSL, SSL_ERROR_SSL, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	if (session != 0) {
		r = SSL_set_session(s->ssl, session);
		if (r == 0) {
			log_ssl_error(ERROR_SSL, SSL_ERROR_SSL, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	}
	SSL_set_app_data(s->ssl, s);
}

static void connect_socket (struct socket_desc* s, struct in_addr a) {
	int r; struct sockaddr_in sa;
	assert(s != 0);
	assert(s->fd == -1);
	s->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (s->fd != -1) {
		set_nonblocking(s->fd);
		set_nodelay(s->fd);
		sa.sin_addr = a;
		sa.sin_port = htons(s->port);
		sa.sin_family = AF_INET;
		r = connect(s->fd, (struct sockaddr *) &sa, sizeof (struct sockaddr));
		if ((r == -1) && (errno != EINTR) && (errno != EINPROGRESS)) {
			log_socket_error(INFO_CONNECTION_FAILURE,
				s->host, s->port, errno, __FILE__, __LINE__);
			if (s->peer != 0) {
				if (s->peer->ssl != 0) {
					shutdown_ssl(s->peer);
				} else {
					close_socket(s->peer);
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
				assert(listener_count > 0);
				listener_count--;
			}
			close_socket(s);
		} else {
			if (s->peer != 0) {
				assert(s->peer->peer == 0);
				s->peer->peer = s;
			}
			if (mode == MODE_CLIENT) {
				prepare_writing_request(s);
				s->ops = OP_WRITE;
				if (yalerssl) {
					init_ssl_client(s, yaler_ssl_session);
					prepare_ssl_handshake(s);
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
				if (s->peer == 0) {
					prepare_writing_request(s);
					s->ops = OP_WRITE;
					if (yalerssl) {
						init_ssl_client(s, yaler_ssl_session);
						prepare_ssl_handshake(s);
					}
				} else {
					prepare_relaying(s);
					begin_relaying(s);
					if (localssl) {
						init_ssl_client(s, local_ssl_session);
						prepare_ssl_handshake(s);
						s->ops = OP_WRITE;
					}
				}
			}
		}
	} else {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void accept_socket (struct socket_desc* s) {
	int fd; struct socket_desc *t;
	assert(buffer_size >= 0);
	assert(s != 0);
	fd = accept(s->fd, 0, 0);
	if (fd != -1) {
		set_nonblocking(fd);
		set_nodelay(fd);
		t = (struct socket_desc *) malloc(
			sizeof (struct socket_desc) + buffer_size);
		if (t != 0) {
			t->next = 0;
			t->peer = 0;
			t->host = s->host;
			t->port = s->port;
			t->domain = 0;
			t->fd = fd;
			t->ops = 0;
			t->state = STATE_OPEN;
			t->read_failed = 0;
			t->write_failed = 0;
			t->stamp = now;
			t->ssl = 0;
			t->ssl_handshake = 0;
			t->ssl_handshake_count = 0;
			t->buffer.position = 0;
			t->buffer.limit = buffer_size;
			t->buffer.data = (char *) t + sizeof (struct socket_desc);
			register_socket(t);
			open_socket(yalerhost, yalerport, yalerdomain, t);
		} else {
			eprintf("%s@%s:%d\n", ERROR_OOM, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR)
		&& (errno != ECONNABORTED) && (errno != EPROTO))
	{
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void bind_socket (struct socket_desc* s, struct in_addr a) {
	int r; struct sockaddr_in sa;
	assert(s != 0);
	assert(s->fd == -1);
	s->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (s->fd != -1) {
		set_nonblocking(s->fd);
		set_reuseaddr(s->fd);
		sa.sin_addr = a;
		sa.sin_port = htons(s->port);
		sa.sin_family = AF_INET;
		r = bind(s->fd, (struct sockaddr *) &sa, sizeof (struct sockaddr));
		if (r != -1) {
			r = listen(s->fd, 64);
			if (r != -1) {
				s->ops = OP_ACCEPT;
			} else {
				log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		} else {
			log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void handle_dns_callback (
	struct dns_ctx* c, struct dns_rr_a4* r, void* d)
{
	struct socket_desc *s;
	assert(d != 0);
	s = (struct socket_desc *) d;
	if ((r != 0) && (r->dnsa4_nrr > 0)) {
		assert(r->dnsa4_addr != 0);
		if (s->ops == OP_BIND) {
			bind_socket(s, r->dnsa4_addr[0]);
		} else {
			assert(s->ops == OP_CONNECT);
			connect_socket(s, r->dnsa4_addr[0]);
		}
	} else if (s->ops == OP_BIND) {
		log_dns_error(ERROR_DNS, s->host, dns_status(c), __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	} else {
		assert(s->ops == OP_CONNECT);
		log_dns_error(INFO_DNS_FAILURE, s->host, dns_status(c), __FILE__, __LINE__);
		if (s->peer != 0) {
			if (s->peer->ssl != 0) {
				shutdown_ssl(s->peer);
			} else {
				close_socket(s->peer);
			}
		} else {
			assert((mode == MODE_SERVER) || (MODE_PROXY));
			assert(listener_count > 0);
			listener_count--;
		}
		close_socket(s);
	}
	if (r != 0) {
		free(r);
	}
}

static void open_socket (
	char* host, int port, char* domain, struct socket_desc* peer)
{
	int r; struct socket_desc *s; struct in_addr a; struct dns_query *q;
	assert(buffer_size >= 0);
	assert(host != 0);
	s = (struct socket_desc *) malloc(
		sizeof (struct socket_desc) + buffer_size);
	if (s != 0) {
		s->next = 0;
		s->peer = peer;
		s->host = host;
		s->port = port;
		s->domain = domain;
		s->fd = -1;
		s->ops = OP_CONNECT;
		s->state = STATE_OPEN;
		s->read_failed = 0;
		s->write_failed = 0;
		s->stamp = now;
		s->ssl = 0;
		s->ssl_handshake = 0;
		s->ssl_handshake_count = 0;
		s->buffer.position = 0;
		s->buffer.limit = buffer_size;
		s->buffer.data = (char *) s + sizeof (struct socket_desc);
		register_socket(s);
		r = dns_pton(AF_INET, host, &a);
		if (r > 0) {
			connect_socket(s, a);
		} else if (r == 0) {
			q = dns_submit_a4(0, host, 0, handle_dns_callback, s);
			if (q == 0) {
				log_dns_error(ERROR_DNS, host, dns_status(0), __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		} else {
			log_dns_error(ERROR_DNS, host, dns_status(0), __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		eprintf("%s@%s:%d\n", ERROR_OOM, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void open_server_socket (char* host, int port) {
	int r; struct socket_desc *s; struct in_addr a; struct dns_query *q;
	assert(host != 0);
	s = (struct socket_desc *) malloc(sizeof (struct socket_desc));
	if (s != 0) {
		s->next = 0;
		s->peer = 0;
		s->host = host;
		s->port = port;
		s->domain = 0;
		s->fd = -1;
		s->ops = OP_BIND;
		s->state = STATE_OPEN;
		s->read_failed = 0;
		s->write_failed = 0;
		s->stamp = now;
		s->ssl = 0;
		s->ssl_handshake = 0;
		s->ssl_handshake_count = 0;
		s->buffer.position = 0;
		s->buffer.limit = 0;
		s->buffer.data = 0;
		register_socket(s);
		r = dns_pton(AF_INET, host, &a);
		if (r > 0) {
			bind_socket(s, a);
		} else if (r == 0) {
			q = dns_submit_a4(0, host, 0, handle_dns_callback, s);
			if (q == 0) {
				log_dns_error(ERROR_DNS, host, dns_status(0), __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		} else {
			log_dns_error(ERROR_DNS, host, dns_status(0), __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		eprintf("%s@%s:%d\n", ERROR_OOM, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void collect_garbage () {
	struct socket_desc *s, *p, *x;
	p = 0;
	s = sockets;
	while (s != 0) {
		if (s->state == STATE_CLOSED) {
			x = s;
			s = s->next;
			if (p == 0) {
				sockets = s;
			} else {
				p->next = s;
			}
			if ((x->host != 0) && (x->host != localhost) && (x->host != yalerhost)) {
				free(x->host);
			}
			if ((x->domain != 0) && (x->domain != yalerdomain)) {
				free(x->domain);
			}
			free(x);
		} else {
			p = s;
			s = s->next;
		}
	}
}

static void test_fds (fd_set* readfds, fd_set* writefds) {
	struct socket_desc *s;
	assert(readfds != 0);
	assert(writefds != 0);
	s = sockets;
	while (s != 0) {
		if (contains(s->ops, OP_ACCEPT)) {
			if (FD_ISSET(s->fd, readfds)) {
				s->stamp = now;
				accept_socket(s);
			}
		} else {
			if (contains(s->ops, OP_READ) && FD_ISSET(s->fd, readfds)) {
				s->stamp = now;
				if (s->ssl_handshake) {
					do_ssl_handshake(s);
				} else if (s->ssl != 0) {
					read_ssl_socket(s);
				} else {
					read_socket(s);
				}
			}
			if (contains(s->ops, OP_WRITE) && FD_ISSET(s->fd, writefds)) {
				s->stamp = now;
				if (s->ssl_handshake) {
					do_ssl_handshake(s);
				} else if (s->ssl != 0) {
					if (s->state == STATE_CLOSING) {
						shutdown_ssl(s);
					} else {
						write_ssl_socket(s);
					}
				} else {
					write_socket(s);
				}
			}
			if ((contains(s->ops, OP_READ) || contains(s->ops, OP_WRITE))
				&& (now > max_idle_time)
				&& (now - max_idle_time > s->stamp))
			{
				eprintf("%s:%s:%d@%s:%d\n", INFO_CONNECTION_TIMEOUT,
					s->host, s->port, __FILE__, __LINE__);
				if (s->peer != 0) {
					if (s->peer->ssl != 0) {
						shutdown_ssl(s->peer);
					} else {
						close_socket(s->peer);
					}
				} else {
					assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
					if ((s->state == STATE_WRITING_REQUEST)
						|| (s->state == STATE_READING_RESPONSE))
					{
						assert(listener_count > 0);
						listener_count--;
					}
				}
				close_socket(s);
			}
		}
		s = s->next;
	}
}

static void set_fds (
	fd_set* readfds, fd_set* writefds, int* maxfd, int* timeout)
{
	int op_read, op_write, t; time_t dt; struct socket_desc *s;
	assert(readfds != 0);
	assert(writefds != 0);
	assert(maxfd != 0);
	assert(timeout != 0);
	*timeout = -1;
	s = sockets;
	while (s != 0) {
		if (contains(s->ops, OP_ACCEPT)) {
			if (socket_count <= max_sockets - 2) {
				FD_SET(s->fd, readfds);
				if (s->fd > *maxfd) {
					*maxfd = s->fd;
				}
			}
		} else {
			op_read = contains(s->ops, OP_READ);
			op_write = contains(s->ops, OP_WRITE);
			if (op_read || op_write) {
				if (op_read) {
					FD_SET(s->fd, readfds);
				}
				if (op_write) {
					FD_SET(s->fd, writefds);
				}
				if (s->fd > *maxfd) {
					*maxfd = s->fd;
				}
				assert(s->stamp <= now);
				dt = now - s->stamp;
				if (dt <= max_idle_time) {
					t = max_idle_time - dt;
					if ((*timeout == -1) || (t < *timeout)) {
						*timeout = t;
					}
				} else {
					*timeout = 0;
				}
			}
		}
		s = s->next;
	}
}

static void run_tunnel () {
	int n, m, r, t, dnsfd, maxfd; fd_set readfds, writefds;
	void (*h)(int); time_t cutoff; struct timeval tv, *timeout;
	h = signal(SIGPIPE, SIG_IGN);
	if (h != SIG_ERR) {
		init_dns(&dnsfd);
		if (localssl || yalerssl) {
			check_openssl_version();
		}
		if (mode == MODE_CLIENT) {
			if (yalerssl) {
				init_ssl_client_ctx(&ssl_client_ctx);
			}
			open_server_socket(localhost, localport);
			assert(listener_count < min_listeners);
			listener_count++;
		} else {
			assert((mode == MODE_SERVER) || (mode == MODE_PROXY));
			if (localssl || yalerssl) {
				init_ssl_client_ctx(&ssl_client_ctx);
			}
		}
		cutoff = 0;
		while (1) {
			now = time(0);
			if (now == (time_t) -1) {
				log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
			timeout = 0;
			maxfd = -1;
			FD_ZERO(&readfds);
			FD_ZERO(&writefds);
			assert(0 <= listener_count);
			assert(listener_count <= min_listeners);
			assert(listener_count <= socket_count);
			assert(socket_count <= max_sockets);
			n = min_listeners - listener_count;
			if (((mode == MODE_SERVER) || (mode == MODE_PROXY)) && (n != 0)) {
				m = (max_sockets - socket_count - listener_count) / 2;
				if (m < n) {
					n = m;
				}
				if (n != 0) {
					if (now < cutoff) {
						timeout = &tv;
						timeout->tv_sec = cutoff - now;
						timeout->tv_usec = 0;
					} else {
						assert(now + 1 > now);
						cutoff = now + 1;
						do {
							open_socket(yalerhost, yalerport, yalerdomain, 0);
							listener_count++;
							n--;
						} while (n != 0);
					}
				}
			}
			t = dns_timeouts(0, -1, now);
			if (t >= 0) {
				if (timeout == 0) {
					timeout = &tv;
					timeout->tv_sec = t;
					timeout->tv_usec = 0;
				} else if (t <= timeout->tv_sec) {
					timeout->tv_sec = t;
					timeout->tv_usec = 0;
				}
				FD_SET(dnsfd, &readfds);
				if (dnsfd > maxfd) {
					maxfd = dnsfd;
				}
			} else {
				assert(t == -1);
				if (((mode == MODE_SERVER) || (mode == MODE_PROXY))
					&& (listener_count < min_listeners)
					&& (timeout == 0))
				{
					timeout = &tv;
					timeout->tv_sec = 0;
					timeout->tv_usec = 0;
				}
			}
			set_fds(&readfds, &writefds, &maxfd, &t);
			if (t >= 0) {
				if (timeout == 0) {
					timeout = &tv;
					timeout->tv_sec = t;
					timeout->tv_usec = 0;
				} else if (t <= timeout->tv_sec) {
					timeout->tv_sec = t;
					timeout->tv_usec = 0;
				}
			}
			assert(maxfd + 1 > maxfd);
			assert((timeout != 0)
				|| ((mode = MODE_CLIENT) && (socket_count == listener_count)));
			r = select(maxfd + 1, &readfds, &writefds, 0, timeout);
			if (r >= 0) {
				if (FD_ISSET(dnsfd, &readfds)) {
					dns_ioevent(0, 0);
				}
				test_fds(&readfds, &writefds);
				collect_garbage();
			} else if ((r == -1) && (errno != EINTR)) {
				log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
			if (dns_status(0) == DNS_E_TEMPFAIL) {
				dns_close(0);
				init_dns(&dnsfd);
			}
		}
	} else {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void print_usage () {
	fprintf(stderr, "YalerTunnel v2.1.0\n"
		"Usage: yalertunnel (client | server | proxy)"
		" [ssl:]<local host>[:<port>]"
		" [ssl:]<yaler host>[:<port>] <yaler domain>"
		" [-min-listeners <number>]"
		" [-max-sockets <number>]"
		" [-buffer-size <number>]\n");
}

static void split_endpoint (char* s, char** host, int* port, int* ssl) {
	char* t;
	assert(s != 0);
	assert(host != 0);
	assert(port != 0);
	assert(ssl != 0);
	if (strstr(s, "ssl:") == s) {
		s += 4;
		*ssl = 1;
	} else {
		*ssl = 0;
	}
	t = strrchr(s, ':');
	if (t != 0) {
		*t = 0;
		*host = s;
		*port = atoi(t + 1);
	} else {
		*host = s;
		*port = *ssl? 443: 80;
	}
}

int main (int argc, char* argv[]) {
	int i;
	if (argc >= 5) {
		if ((strcmp(argv[1], "client") == 0)
			|| (strcmp(argv[1], "server") == 0)
			|| (strcmp(argv[1], "proxy") == 0))
		{
			mode = argv[1][0];
			split_endpoint(argv[2], &localhost, &localport, &localssl);
			split_endpoint(argv[3], &yalerhost, &yalerport, &yalerssl);
			yalerdomain = argv[4];
			i = 5;
			while ((i != argc) && (i != -1)) {
				if (i + 1 != argc) {
					if (strcmp(argv[i], "-min-listeners") == 0) {
						min_listeners = atoi(argv[i + 1]);
						i += 2;
					} else if (strcmp(argv[i], "-max-sockets") == 0) {
						max_sockets = atoi(argv[i + 1]);
						i += 2;
					} else if (strcmp(argv[i], "-buffer-size") == 0) {
						buffer_size = atoi(argv[i + 1]);
						i += 2;
					} else if (strcmp(argv[i], "-relay-security") == 0) {
						if (strcmp(argv[i + 1], "transport/pass-through") == 0) {
							relay_security = RELAY_SECURITY_TRANSPORT_PASSTHROUGH;
							i += 2;
						} else {
							i = -1;
						}
					} else {
						i = -1;
					}
				} else {
					i = -1;
				}
			}
			if ((i == argc)
				&& (min_listeners > 0)
				&& (max_sockets > min_listeners)
				&& (buffer_size > 0))
			{
				run_tunnel();
			} else {
				print_usage();
			}
		} else {
			print_usage();
		}
	} else {
		print_usage();
	}
	exit(EXIT_FAILURE);
}
