/*
** Copyright (c) 2019, Yaler GmbH, Switzerland
** All rights reserved
*/

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>

#include <openssl/ssl.h>

#include "tls/tls_verify.h"
#include "udns/udns.h"

#include "http_reader.h"

#define VERSION "v2.3.0"

#define HT 9
#define SP 32

#define MODE_CLIENT 'c'
#define MODE_SERVER 's'
#define MODE_DSERVER 'd'
#define MODE_PROXY 'p'

#define RELAY_SECURITY_TRANSPORT_PASSTHROUGH 1

#define HOST_MAX 255
#define DOMAIN_MAX 255

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
#define ERROR_DNS "error:DNS"
#define ERROR_LOADING_CA_FILE_FAILURE "error:loading <ca-file> failed"
#define ERROR_OOM "error:out of memory"
#define ERROR_SSL "error:TLS"
#define ERROR_SYSCALL "error:system call"

#define WARNING_OPENSSL_VERSION_MISMATCH "warning:OpenSSL version mismatch"

#define INFO_BUILT_WITH "built with"
#define INFO_CERTIFICATE_VERIFICATION_FAILURE "certificate verification failure"
#define INFO_CLIENT_INITIATED_RENEGOTIATION "client-initiated renegotiation"
#define INFO_CONNECTION_FAILURE "connection failure"
#define INFO_CONNECTION_TIMEOUT "connection timeout"
#define INFO_DNS_FAILURE "DNS failure"
#define INFO_DROPPING_DATAGRAM "dropping datagram"
#define INFO_RETRY_AFTER "retry after"
#define INFO_TOO_MANY_REQUESTS "too many requests"
#define INFO_UNEXPECTED_REQUEST "unexpected request"
#define INFO_UNEXPECTED_RESPONSE "unexpected response"
#define INFO_USING "using"

#define SCHEME_NONE 0
#define SCHEME_HTTP 1
#define SCHEME_HTTPS 2

#define TIMEOUT_MAX_SEC 2678400

#define A 48271
#define M 2147483647
#define Q (M / A)
#define R (M % A)

#ifndef ENONET
#define ENONET ENETDOWN
#endif

struct buffer {
	size_t position, limit;
	char *data;
};

struct socket_desc {
	struct socket_desc *next, *peer;
	int type;
	char host[HOST_MAX + 1];
	int port;
	char domain[DOMAIN_MAX + 1];
	int fd, ops, state;
	int read_failed, write_failed;
	struct timeval stamp;
	struct dns_query *q;
	SSL *ssl;
	int ssl_handshake;
	int ssl_handshake_count;
	int ssl_handshake_stash;
	struct http_reader http_reader;
	size_t http_reader_position;
	int http_error;
	char *http_method;
	size_t http_method_length;
	char *http_status;
	size_t http_status_length;
	char *http_location;
	size_t http_location_length;
	char *http_retry_after;
	size_t http_retry_after_length;
	char *http_header_name;
	size_t http_header_name_length;
	char *http_header_value;
	size_t http_header_value_length;
	struct buffer buffer;
	size_t dgram_drop_count;
};

static int mode;

static int localssl;
static char *localhost;
static int localport;

static int yalerssl;
static char *yalerhost;
static int yalerport;
static char *yalerdomain;

static char host[HOST_MAX + 1];
static char domain[DOMAIN_MAX + 1];

static char *secret_key = NULL;
static char *ca_file = NULL;
static int certificate_verification = 1;
static int min_listeners = 1;
static int max_sockets = 128;
static int buffer_size = 16384;
static int relay_security = 0;
static int max_idle_time = 75;

static struct timeval now = {0, 0};
static SSL_CTX *ssl_client_ctx = NULL;
static SSL_SESSION *yaler_ssl_session = NULL;
static SSL_SESSION *local_ssl_session = NULL;
static struct socket_desc *sockets = NULL;
static int socket_count = 0;
static int listener_count = 0;
static int socket_pair_count = 0;

static struct timeval retry_cutoff = {0, 0};
static int retry_count = 0;

static int seed;

static void open_socket(
	int type, char *host, int port, char *domain, struct socket_desc *peer);

static int contains(int set, int bits) {
	return (set & bits) == bits;
}

static void include(int *set, int bits) {
	assert(set != NULL);
	*set |= bits;
}

static void exclude(int *set, int bits) {
	assert(set != NULL);
	*set &= ~bits;
}

static void clear_buffer(struct buffer *b) {
	assert(buffer_size >= 0);
	assert(b != NULL);
	b->position = 0;
	b->limit = buffer_size;
}

static void flip_buffer(struct buffer *b) {
	assert(b != NULL);
	b->limit = b->position;
	b->position = 0;
}

static void compact_buffer(struct buffer *b) {
	assert(buffer_size >= 0);
	assert(b != NULL);
	assert(b->data != NULL);
	assert(b->position <= b->limit);
	assert(b->limit <= (size_t)buffer_size);
	memmove(b->data, &b->data[b->position], b->limit - b->position);
	b->position = b->limit - b->position;
	b->limit = buffer_size;
}

static size_t dgram_length(char *buffer) {
	assert(buffer != NULL);
	return (buffer[0] & 0xff) | ((buffer[1] & 0xff) << 8);
}

static void get_time(struct timeval *tv) {
	int r;
	assert(tv != NULL);
	r = gettimeofday(tv, NULL);
	if (r != 0) {
		assert(r == -1);
		fprintf(stderr, "gettimeofday:%d:%s@%s:%d\n",
			errno, strerror(errno), __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

/*
	Random number generator based on S. K. Park and K. W. Miller (1988), "Random
	Number Generators: Good Ones Are Hard To Find", CACM 31 (10): 1192–1201 and
	D. Crawford	(1993), "Technical correspondence", CACM 36 (7): 105-110.
*/

static void init_seed(int s) {
	assert(INT_MIN <= -2147483647 - 1);
	assert(INT_MAX >= 2147483647);
	s %= M - 1;
	seed = s < 0? 1 - s: 1 + s;
	assert(seed >= 1);
	assert(seed < M);
}

static double random_number() {
	assert(seed >= 1);
	assert(seed < M);
	seed = A * (seed % Q) - R * (seed / Q);
	if (seed < 0) {
		seed += M;
	}
	assert(seed >= 1);
	assert(seed < M);
	return (double)seed / M;
}

/*
	Delay in msec depending on the number of retries:
		1 second for 3 minutes,
		then 15 seconds for 3 hours,
		then 15 minutes for 3 days,
		then 6 hours for 3 months,
*/

int msec_delay(int retry_count) {
	int r;
	assert(retry_count >= 0);
	if (retry_count < 180) {
		r = 1000;
	} else if (retry_count < 900) {
		r = 15000;
	} else if (retry_count < 1188) {
		r = 900000;
	} else if (retry_count < 1548) {
		r = 21600000;
	} else {
		r = -1;
	}
	return r;
}

int randomized(int n) {
	int d;
	assert(n >= 0);
	assert(n <= INT_MAX - n / 3);
	d = n / 3;
	return n - d + random_number() * (2 * d + 1);
}

static char *ssl_error_msg(int ssl_error) {
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

static void eprintf(char *format, ...) {
	struct tm *gmt; va_list args;
	assert(format != NULL);
	gmt = gmtime(&now.tv_sec);
	if (gmt != NULL) {
		fprintf(stderr, "%04d-%02d-%02d'T'%02d:%02d:%02d'Z':",
			1900 + gmt->tm_year, 1 + gmt->tm_mon, gmt->tm_mday,
			gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
	}
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fflush(stderr);
}

static void eprintf_buffer(struct buffer *b) {
	size_t i, j, n;
	assert(b != NULL);
	assert(b->data != NULL);
	i = 0; j = b->position;
	if (i == j) {
		fprintf(stderr, "\n");
	} else {
		do {
			fprintf(stderr, "    %04zx", i);
			for (n = 0; n != 16; n++) {
					if (n % 4 == 0) {
							fprintf(stderr, " ");
					}
					if ((n <= j) && (i < j - n)) {
							fprintf(stderr, "%02x", b->data[i + n] & 0xff);
					} else {
							fprintf(stderr, "  ");
					}
			};
			fprintf(stderr, "    ");
			for (n = 0; n != 16; n++) {
					if (i != j) {
							if ((32 <= b->data[i]) && (b->data[i] < 127)) {
									fprintf(stderr, "%c", b->data[i]);
							} else {
									fprintf(stderr, ".");
							}
							i++;
					}
			}
			fprintf(stderr, "\n");
		} while (i != j);
	}
	fflush(stderr);
}

static void log_error(char *msg, int error, char *file, int line) {
	assert(msg != NULL);
	assert(file != NULL);
	if (error != 0) {
		eprintf("%s:%d:%s@%s:%d\n", msg, error, strerror(error), file, line);
	} else {
		eprintf("%s@%s:%d\n", msg, file, line);
	}
}

static void log_dns_error(char *msg, char *host,
	int dns_error, char *file, int line)
{
	assert(msg != NULL);
	assert(host != NULL);
	assert(file != NULL);
	eprintf("%s:%d:%s:%s@%s:%d\n",
		msg, dns_error, dns_strerror(dns_error), host, file, line);
}

static void log_ssl_error(char *msg, int ssl_error, char *file, int line) {
	assert(msg != NULL);
	assert(file != NULL);
	if ((ssl_error == SSL_ERROR_SYSCALL) && (errno != 0)) {
		eprintf("%s:%d:%s:@%s:%d\n",
			msg, errno, strerror(errno), file, line);
	} else {
		eprintf("%s:%d:%s@%s:%d\n",
			msg, ssl_error, ssl_error_msg(ssl_error), file, line);
	}
}

static void log_socket_error(char *msg, char *host, int port,
	int error, char *file, int line)
{
	assert(msg != NULL);
	assert(host != NULL);
	assert(file != NULL);
	if (error != 0) {
		eprintf("%s:%d:%s:%s:%d@%s:%d\n",
			msg, error, strerror(error), host, port, file, line);
	} else {
		eprintf("%s:%s:%d@%s:%d\n",
			msg, host, port, file, line);
	}
}

static void log_dgram_error(char *msg, char *host, int port,
	size_t size, char *file, int line)
{
	assert(msg != NULL);
	assert(host != NULL);
	assert(file != NULL);
	eprintf("%s:%zu:%s:%d@%s:%d\n",
		msg, size, host, port, file, line);
}

static void log_ssl_socket_error(char *msg, char *host, int port,
	int ssl_error, char *file, int line)
{
	assert(msg != NULL);
	assert(host != NULL);
	assert(file != NULL);
	if ((ssl_error == SSL_ERROR_SYSCALL) && (errno != 0)) {
		eprintf("%s:%d:%s:%s:%d@%s:%d\n",
			msg, errno, strerror(errno), host, port, file, line);
	} else {
		eprintf("%s:%d:%s:%s:%d@%s:%d\n",
			msg, ssl_error, ssl_error_msg(ssl_error), host, port, file, line);
	}
}

static void log_protocol_error(char *msg, char *host, int port,
	struct buffer *b, char *file, int line)
{
	assert(msg != NULL);
	assert(host != NULL);
	assert(b != NULL);
	assert(file != NULL);
	eprintf("%s:%s:%d:%d@%s:%d\n", msg, host, port, b->position, file, line);
	eprintf_buffer(b);
}

static void *alloc(size_t size) {
	void *r;
	r = malloc(size);
	if (r == NULL) {
		eprintf("%s@%s:%d\n", ERROR_OOM, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	return r;
}

static void init_signal_handling() {
	void (*h)(int);
	h = signal(SIGPIPE, SIG_IGN);
	if (h == SIG_ERR) {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void set_nonblocking(int fd) {
	int r;
	r = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (r == -1) {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void set_reuseaddr(int fd) {
	int r, v;
	v = 1;
	r = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v);
	if (r != 0) {
		assert(r == -1);
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void set_nodelay(int fd) {
	int r, v;
	v = 1;
	r = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof v);
	if (r != 0) {
		assert(r == -1);
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void init_dns(int *fd) {
	int r;
	assert(fd != NULL);
	r = dns_init(NULL, /* do_open: */ 1);
	if (r >= 0) {
		*fd = r;
		r = dns_set_opts(NULL, "udpbuf:512");
		if (r != 0) {
			eprintf("%s:%s@%s:%d\n", ERROR_DNS, "dns_set_opts", __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		eprintf("%s:%s@%s:%d\n", ERROR_DNS, "dns_init", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void update_ssl_session(SSL *ssl, SSL_SESSION **session) {
	assert(ssl != NULL);
	assert(session != NULL);
	if (!SSL_session_reused(ssl)) {
		if (*session != NULL) {
			SSL_SESSION_free(*session);
		}
		*session = SSL_get1_session(ssl);
	}
}

static void handle_ssl_info(const SSL *ssl, int where, int r) {
	struct socket_desc *s;
	(void)r;
	if (contains(where, SSL_CB_HANDSHAKE_START)) {
		s = (struct socket_desc*)SSL_get_app_data(ssl);
		assert(s != NULL);
		if (s->ssl_handshake_count < INT_MAX) {
			s->ssl_handshake_count++;
		}
	}
}

static void init_ssl_client_ctx(SSL_CTX **c) {
	int r; long v;
	assert(c != NULL);
	v = SSLeay();
	if (v != OPENSSL_VERSION_NUMBER) {
		eprintf("%s:%s: %lx, %s: %lx\n", WARNING_OPENSSL_VERSION_MISMATCH,
			INFO_BUILT_WITH, OPENSSL_VERSION_NUMBER, INFO_USING, v);
	}
	SSL_library_init();
	SSL_load_error_strings();
	*c = SSL_CTX_new(SSLv23_client_method());
	if (*c != NULL) {
		SSL_CTX_set_mode(*c, SSL_MODE_ENABLE_PARTIAL_WRITE);
		SSL_CTX_set_mode(*c, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
		SSL_CTX_set_options(*c, SSL_OP_NO_SSLv2);
		SSL_CTX_set_options(*c, SSL_OP_NO_SSLv3);
		SSL_CTX_set_info_callback(*c, handle_ssl_info);
		if (certificate_verification) {
			SSL_CTX_set_verify(*c, SSL_VERIFY_PEER, NULL);
		}
		if (ca_file == NULL) {
			r = SSL_CTX_set_default_verify_paths(*c);
			if (r != 1) {
				assert(r == 0);
				log_ssl_error(ERROR_SSL, SSL_ERROR_SSL, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		} else {
			r = SSL_CTX_load_verify_locations(*c, ca_file, NULL);
			if (r != 1) {
				assert(r == 0);
				eprintf("%s@%s:%d\n", ERROR_LOADING_CA_FILE_FAILURE, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		}
	} else {
		log_ssl_error(ERROR_SSL, SSL_ERROR_SSL, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void register_socket(struct socket_desc *s) {
	assert(socket_count < max_sockets);
	assert(s != NULL);
	assert(s->next == NULL);
	s->next = sockets;
	sockets = s;
	socket_count++;
	if (s->peer != NULL) {
		assert(socket_pair_count < socket_count / 2);
		socket_pair_count++;
	}
}

static void close_socket(struct socket_desc *s) {
	int r;
	assert(socket_count > 0);
	assert(s != NULL);
	assert(s->state != STATE_CLOSED);
	if ((s->peer != NULL) && (s->peer->state == STATE_CLOSED)) {
		assert(socket_pair_count > 0);
		socket_pair_count--;
	}
	if (s->q != NULL) {
		dns_cancel(NULL, s->q);
		s->q = NULL;
	}
	if (s->ssl != NULL) {
		SSL_set_shutdown(s->ssl, SSL_SENT_SHUTDOWN);
		SSL_free(s->ssl);
		s->ssl = NULL;
	}
	if (s->fd != -1) {
		shutdown(s->fd, SHUT_RDWR);
		r = close(s->fd);
		if (r != 0) {
			assert(r == -1);
			log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
		s->fd = -1;
	}
	s->ops = 0;
	s->state = STATE_CLOSED;
	socket_count--;
}

static int listener_delta() {
	int n, m;
	assert(0 <= listener_count);
	if (mode == MODE_CLIENT) {
		assert(listener_count <= 1);
		n = 1 - listener_count;
	} else {
		assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
			|| (mode == MODE_PROXY));
		assert(listener_count <= min_listeners);
		n = min_listeners - listener_count;
		if (n != 0) {
			assert(listener_count <= socket_count);
			assert(socket_count <= max_sockets);
			assert(socket_pair_count >= 0);
			assert(socket_pair_count <= socket_count / 2);
			m = max_sockets / 2 - (socket_count - socket_pair_count);
			if (m < n) {
				assert(m >= 0);
				n = m;
			}
		}
	}
	return n;
}

static void shutdown_ssl(struct socket_desc *s) {
	int r;
	assert(s != NULL);
	assert(s->ssl != NULL);
	r = SSL_shutdown(s->ssl);
	if (r < 0) {
		r = SSL_get_error(s->ssl, r);
		if (r == SSL_ERROR_WANT_WRITE) {
			s->ops = OP_WRITE;
			s->state = STATE_CLOSING;
		} else {
			close_socket(s);
		}
	} else {
		assert((r == 0) || (r == 1));
		close_socket(s);
	}
}

static void prepare_ssl_handshake(struct socket_desc *s) {
	assert(s != NULL);
	assert(!s->ssl_handshake);
	if (s->peer != NULL) {
		assert(!s->peer->ssl_handshake);
		s->peer->ssl_handshake_stash = s->peer->ops;
		s->peer->ops = 0;
	}
	s->ssl_handshake_stash = s->ops;
	s->ssl_handshake = 1;
}

static void prepare_writing_request(struct socket_desc *s) {
	int r, i;
	assert(buffer_size >= 0);
	assert(s != NULL);
	assert(s->host != NULL);
	assert(s->domain != NULL);
	assert(s->buffer.data != NULL);
	s->state = STATE_WRITING_REQUEST;
	if (mode == MODE_CLIENT) {
		r = snprintf(s->buffer.data, buffer_size,
			"CONNECT /%s HTTP/1.1\r\n"
			"Host: %s:%d\r\n"
			"User-Agent: YalerTunnel/" VERSION "\r\n"
			"Content-Length: 0\r\n\r\n",
			s->domain, s->host, s->port);
		if ((r < 0) || (r >= buffer_size)) {
			eprintf("%s@%s:%d\n", ERROR_CONFIG, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
		s->buffer.limit = r;
		s->buffer.position = 0;
	} else {
		i = 0;
		if ((mode == MODE_SERVER) || (mode == MODE_PROXY)) {
			r = snprintf(&s->buffer.data[i], buffer_size - i,
				"POST /%s HTTP/1.1\r\n"
				"Upgrade: PTTH/1.0\r\n"
				"Connection: Upgrade\r\n"
				"Host: %s:%d\r\n",
				s->domain, s->host, s->port);
		} else {
			assert(mode == MODE_DSERVER);
			r = snprintf(&s->buffer.data[i], buffer_size - i,
				"POST /%s HTTP/1.1\r\n"
				"Upgrade: DPTTH/1.0\r\n"
				"Connection: Upgrade\r\n"
				"Host: %s:%d\r\n",
				s->domain, s->host, s->port);
		}
		if ((r < 0) || (r >= buffer_size - i)) {
			eprintf("%s@%s:%d\n", ERROR_CONFIG, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
		i += r;
		if (secret_key != NULL) {
			r = snprintf(&s->buffer.data[i], buffer_size - i,
				"Authorization: Bearer %s\r\n", secret_key);
			if ((r < 0) || (r >= buffer_size - i)) {
				eprintf("%s@%s:%d\n", ERROR_CONFIG, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
			i += r;
		}
		if (relay_security == RELAY_SECURITY_TRANSPORT_PASSTHROUGH) {
			r = snprintf(&s->buffer.data[i], buffer_size - i,
				"X-Relay-Security: transport/pass-through\r\n");
			if ((r < 0) || (r >= buffer_size - i)) {
				eprintf("%s@%s:%d\n", ERROR_CONFIG, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
			i += r;
		} else {
			assert(relay_security == 0);
		}
		r = snprintf(&s->buffer.data[i], buffer_size - i,
			"User-Agent: YalerTunnel/" VERSION "\r\n"
			"Content-Length: 0\r\n\r\n");
		if ((r < 0) || (r >= buffer_size - i)) {
			eprintf("%s@%s:%d\n", ERROR_CONFIG, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
		i += r;
		s->buffer.limit = i;
		s->buffer.position = 0;
	}
}

static void prepare_reading_response(struct socket_desc *s) {
	assert(s != NULL);
	s->state = STATE_READING_RESPONSE;
	http_reader_init(&s->http_reader, HTTP_READER_TYPE_RESPONSE);
	s->http_reader_position = 0;
	s->http_error = 0;
	s->http_status = NULL;
	s->http_location = NULL;
	s->http_retry_after = NULL;
	s->http_header_name = NULL;
	s->http_header_value = NULL;
}

static void prepare_reading_request(struct socket_desc *s) {
	assert(s != NULL);
	s->state = STATE_READING_REQUEST;
	http_reader_init(&s->http_reader, HTTP_READER_TYPE_REQUEST);
	s->http_reader_position = 0;
	s->http_error = 0;
	s->http_method = NULL;
	s->http_header_name = NULL;
	s->http_header_value = NULL;
}

static void prepare_writing_response(struct socket_desc *s) {
	int r;
	assert(buffer_size >= 0);
	assert(s != NULL);
	assert(s->buffer.data != NULL);
	s->state = STATE_WRITING_RESPONSE;
	r = snprintf(s->buffer.data, buffer_size,
		"HTTP/1.1 200 OK\r\n\r\n");
	if ((r < 0) || (r >= buffer_size)) {
		eprintf("%s@%s:%d\n", ERROR_CONFIG, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	s->buffer.limit = r;
	s->buffer.position = 0;
}

static void handle_dgram_buffer(struct socket_desc *s) {
	size_t n; struct buffer *b;
	assert(s != NULL);
	assert(s->type == SOCK_STREAM);
	assert(s->state == STATE_RELAYING);
	assert(s->peer != NULL);
	assert(s->peer->type == SOCK_DGRAM);
	assert(s->peer->state == STATE_RELAYING);
	b = &s->buffer;
	assert(b->data != NULL);
	assert(b->limit >= 2);
	assert(b->limit >= b->position);
	if (s->dgram_drop_count != 0) {
		if (s->dgram_drop_count < b->position) {
			b->limit = b->position;
			b->position = s->dgram_drop_count;
			s->dgram_drop_count -= b->position;
			compact_buffer(b);
		} else {
			s->dgram_drop_count -= b->position;
			clear_buffer(b);
		}
	}
	if (s->dgram_drop_count == 0) {
		if (b->position >= 2) {
			n = dgram_length(b->data);
			if (b->position - 2 >= n) {
				flip_buffer(b);
				exclude(&s->ops, OP_READ);
				include(&s->peer->ops, OP_WRITE);
			} else {
				if (b->limit - 2 < n) {
					log_dgram_error(INFO_DROPPING_DATAGRAM,
						s->host, s->port, n, __FILE__, __LINE__);
					s->dgram_drop_count = n - (b->position - 2);
					clear_buffer(b);
				}
				include(&s->ops, OP_READ);
			}
		} else {
			include(&s->ops, OP_READ);
		}
	} else {
		assert(contains(s->ops, OP_READ));
	}
}

static void prepare_relaying(struct socket_desc *s) {
	assert(s != NULL);
	assert(s->peer != NULL);
	s->state = STATE_RELAYING;
	s->peer->state = STATE_RELAYING;
	s->ops = 0;
	s->peer->ops = 0;
	if (s->buffer.position == 0) {
		include(&s->ops, OP_READ);
	} else if (s->peer->type == SOCK_STREAM) {
		flip_buffer(&s->buffer);
		include(&s->peer->ops, OP_WRITE);
	} else {
		handle_dgram_buffer(s);
	}
	if (s->peer->buffer.position == 0) {
		include(&s->peer->ops, OP_READ);
	} else if (s->type == SOCK_STREAM) {
		flip_buffer(&s->peer->buffer);
		include(&s->ops, OP_WRITE);
	} else {
		handle_dgram_buffer(s->peer);
	}
}

static void handle_unexpected_request(
	struct socket_desc *s, char *file, int line)
{
	assert(mode == MODE_PROXY);
	assert(s != NULL);
	assert(s->state == STATE_READING_REQUEST);
	log_protocol_error(INFO_UNEXPECTED_REQUEST,
		s->host, s->port, &s->buffer, file, line);
	assert(s->peer == NULL);
	if (s->ssl != NULL) {
		shutdown_ssl(s);
	} else {
		close_socket(s);
	}
}

static void handle_unexpected_response(
	struct socket_desc *s, char *file, int line)
{
	assert(s != NULL);
	assert(s->state == STATE_READING_RESPONSE);
	log_protocol_error(INFO_UNEXPECTED_RESPONSE,
		s->host, s->port, &s->buffer, file, line);
	if (mode == MODE_CLIENT) {
		assert(s->peer != NULL);
		assert(s->peer->state == STATE_OPEN);
		if (s->peer->ssl != NULL) {
			shutdown_ssl(s->peer);
		} else {
			close_socket(s->peer);
		}
	} else {
		assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
			|| (mode == MODE_PROXY));
		assert(s->peer == NULL);
		assert(listener_count > 0);
		listener_count--;
	}
	if (s->ssl != NULL) {
		shutdown_ssl(s);
	} else {
		close_socket(s);
	}
}

static void handle_request(struct socket_desc *s, int *done) {
	assert(mode == MODE_PROXY);
	assert(s != NULL);
	assert(s->state == STATE_READING_REQUEST);
	assert(s->http_reader.state == HTTP_READER_STATE_DONE);
	assert(s->http_method != NULL);
	assert(done != NULL);
	*done = 1;
	if ((s->http_method_length == 7)
		&& (strncmp(s->http_method, "CONNECT", 7) == 0)
		&& (s->http_reader_position == s->buffer.position))
	{
		prepare_writing_response(s);
		s->ops = OP_WRITE;
	} else {
		handle_unexpected_request(s, __FILE__, __LINE__);
	}
}

static void delay_retry(struct socket_desc *s) {
	size_t i, j; int delay, d; struct timeval tv; struct tm *gmt;
	assert(s != NULL);
	if (s->http_retry_after != NULL) {
		i = 0; j = s->http_retry_after_length;
		while ((i != j)
			&& ((s->http_retry_after[i] == SP) || (s->http_retry_after[i] == HT)))
		{
			i++;
		}
		if ((i != j)
			&& ('0' <= s->http_retry_after[i]) && (s->http_retry_after[i] <= '9'))
		{
			delay = s->http_retry_after[i] - '0';
			i++;
			while ((i != j)
				&& ('0' <= s->http_retry_after[i]) && (s->http_retry_after[i] <= '9'))
			{
				d = s->http_retry_after[i] - '0';
				if (delay <= (INT_MAX - d) / 10) {
					delay = 10 * delay + d;
					i++;
				} else {
					delay = INT_MAX;
				}
			}
			while ((i != j)
				&& ((s->http_retry_after[i] == SP) || (s->http_retry_after[i] == HT)))
			{
				i++;
			}
			if (i == j) {
				if (mode == MODE_CLIENT) {
					assert(s->peer != NULL);
					assert(s->peer->state == STATE_OPEN);
					if (s->peer->ssl != NULL) {
						shutdown_ssl(s->peer);
					} else {
						close_socket(s->peer);
					}
				} else {
					assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
						|| (mode == MODE_PROXY));
					assert(s->peer == NULL);
					assert(listener_count > 0);
					listener_count--;
				}
				if (s->ssl != NULL) {
					shutdown_ssl(s);
				} else {
					close_socket(s);
				}
				tv.tv_sec = now.tv_sec + (time_t)delay;
				tv.tv_usec = now.tv_usec;
				if ((retry_cutoff.tv_sec < now.tv_sec)
					|| ((retry_cutoff.tv_sec == now.tv_sec)
						&& (retry_cutoff.tv_usec < now.tv_usec))
					|| (tv.tv_sec < retry_cutoff.tv_sec)
					|| ((tv.tv_sec == retry_cutoff.tv_sec)
						&& (tv.tv_usec < retry_cutoff.tv_usec)))
				{
					retry_cutoff = tv;
					retry_count = 0;
					gmt = gmtime(&retry_cutoff.tv_sec);
					if (gmt != NULL) {
						eprintf("%s:%s:%s:%04d-%02d-%02d'T'%02d:%02d:%02d'Z'@%s:%d\n",
							INFO_UNEXPECTED_RESPONSE,
							INFO_TOO_MANY_REQUESTS,
							INFO_RETRY_AFTER,
							1900 + gmt->tm_year, 1 + gmt->tm_mon, gmt->tm_mday,
							gmt->tm_hour, gmt->tm_min, gmt->tm_sec,
							__FILE__, __LINE__);
					} else {
						eprintf("%s:%s@%s:%d\n",
							INFO_UNEXPECTED_RESPONSE,
							INFO_TOO_MANY_REQUESTS,
							__FILE__, __LINE__);
					}
				}
			} else {
				handle_unexpected_response(s, __FILE__, __LINE__);
			}
		} else {
			handle_unexpected_response(s, __FILE__, __LINE__);
		}
	} else {
		handle_unexpected_response(s, __FILE__, __LINE__);
	}
}

static void handle_redirect(struct socket_desc *s) {
	size_t i, j, hpos, hlen, dpos, dlen; int scheme, port, p;
	assert(s != NULL);
	if (s->http_location != NULL) {
		i = 0; j = s->http_location_length;
		while ((i != j)
			&& ((s->http_location[i] == SP) || (s->http_location[i] == HT)))
		{
			i++;
		}
		if ((j - i >= 8)
			&& ((s->http_location[i] == 'h') || (s->http_location[i] == 'H'))
			&& ((s->http_location[i + 1] == 't') || (s->http_location[i + 1] == 'T'))
			&& ((s->http_location[i + 2] == 't') || (s->http_location[i + 2] == 'T'))
			&& ((s->http_location[i + 3] == 'p') || (s->http_location[i + 3] == 'P'))
			&& ((s->http_location[i + 4] == 's') || (s->http_location[i + 4] == 'S'))
			&& (s->http_location[i + 5] == ':')
			&& (s->http_location[i + 6] == '/')
			&& (s->http_location[i + 7] == '/'))
		{
			scheme = SCHEME_HTTPS;
			i += 8;
		} else if ((j - i >= 7)
			&& ((s->http_location[i] == 'h') || (s->http_location[i] == 'H'))
			&& ((s->http_location[i + 1] == 't') || (s->http_location[i + 1] == 'T'))
			&& ((s->http_location[i + 2] == 't') || (s->http_location[i + 2] == 'T'))
			&& ((s->http_location[i + 3] == 'p') || (s->http_location[i + 3] == 'P'))
			&& (s->http_location[i + 4] == ':')
			&& (s->http_location[i + 5] == '/')
			&& (s->http_location[i + 6] == '/'))
		{
			scheme = SCHEME_HTTP;
			i += 7;
		} else {
			scheme = SCHEME_NONE;
		}
		if (((scheme == SCHEME_HTTPS) || (scheme == SCHEME_HTTP)) && (i != j)) {
			hpos = i;
			while ((i != j)
				&& (s->http_location[i] != ':') && (s->http_location[i] != '/'))
			{
				i++;
			}
			hlen = i - hpos;
			if ((i != j) && (s->http_location[i] == ':')) {
				i++;
				if ((i != j)
					&& ('0' <= s->http_location[i]) && (s->http_location[i] <= '9'))
				{
					port = 0;
					do {
						p = s->http_location[i] - '0';
						if (port <= (65535 - p) / 10) {
							port = 10 * port + p;
							i++;
						} else {
							port = -1;
						}
					} while ((port >= 0) && (i != j)
						&& ('0' <= s->http_location[i]) && (s->http_location[i] <= '9'));
				} else if (scheme == SCHEME_HTTPS) {
					port = 443;
				} else {
					assert(scheme == SCHEME_HTTP);
					port = 80;
				}
			} else if (scheme == SCHEME_HTTPS) {
				port = 443;
			} else {
				assert(scheme == SCHEME_HTTP);
				port = 80;
			}
			if ((port >= 0) && (i != j) && (s->http_location[i] == '/')) {
				i++;
				dpos = i;
				while ((i != j)
					&& (s->http_location[i] != SP) && (s->http_location[i] != HT))
				{
					i++;
				}
				dlen = i - dpos;
				while ((i != j)
					&& ((s->http_location[i] == SP) || (s->http_location[i] == HT)))
				{
					i++;
				}
				if ((i == j) && (hlen <= HOST_MAX) && (dlen <= DOMAIN_MAX)) {
					if (s->ssl != NULL) {
						shutdown_ssl(s);
					} else {
						close_socket(s);
					}
					assert(sizeof host > HOST_MAX);
					memcpy(host, &s->http_location[hpos], hlen);
					host[hlen] = 0;
					assert(sizeof domain > DOMAIN_MAX);
					memcpy(domain, &s->http_location[dpos], dlen);
					domain[dlen] = 0;
					if (s->peer != NULL) {
						assert(s->peer->ops == 0);
						assert(s->peer->state == STATE_OPEN);
						s->peer->peer = NULL;
						assert(socket_pair_count > 0);
						socket_pair_count--;
					}
					open_socket(s->type, host, port, domain, s->peer);
				} else {
					handle_unexpected_response(s, __FILE__, __LINE__);
				}
			} else {
				handle_unexpected_response(s, __FILE__, __LINE__);
			}
		} else {
			handle_unexpected_response(s, __FILE__, __LINE__);
		}
	} else {
		handle_unexpected_response(s, __FILE__, __LINE__);
	}
}

static void handle_response(struct socket_desc *s, int *done) {
	assert(s != NULL);
	assert(s->state == STATE_READING_RESPONSE);
	assert(s->http_reader.state == HTTP_READER_STATE_DONE);
	assert(s->http_status != NULL);
	assert(done != NULL);
	*done = 1;
	if (s->http_status_length == 3) {
		if ((s->http_status[0] == '1')
			&& ((s->http_status[1] != '0')
				|| (s->http_status[2] != '1')))
		{
			s->buffer.limit = s->buffer.position;
			s->buffer.position = s->http_reader_position;
			compact_buffer(&s->buffer);
			prepare_reading_response(s);
			if (s->buffer.position != 0) {
				*done = 0;
			}
		} else if ((strncmp(s->http_status, "307", 3) == 0)
			|| (strncmp(s->http_status, "308", 3) == 0))
		{
			handle_redirect(s);
		} else {
			if (mode == MODE_CLIENT) {
				if (strncmp(s->http_status, "200", 3) == 0) {
					s->buffer.limit = s->buffer.position;
					s->buffer.position = s->http_reader_position;
					compact_buffer(&s->buffer);
					prepare_relaying(s);
				} else {
					handle_unexpected_response(s, __FILE__, __LINE__);
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
					|| (mode == MODE_PROXY));
				if (strncmp(s->http_status, "101", 3) == 0) {
					if (retry_count != 0) {
						retry_cutoff.tv_sec = 0;
						retry_cutoff.tv_usec = 0;
						retry_count = 0;
					}
					s->buffer.limit = s->buffer.position;
					s->buffer.position = s->http_reader_position;
					compact_buffer(&s->buffer);
					assert(listener_count > 0);
					listener_count--;
					if (mode == MODE_SERVER) {
						s->ops = 0;
						s->state = STATE_OPEN;
						open_socket(SOCK_STREAM, localhost, localport, NULL, s);
					} else if (mode == MODE_DSERVER) {
						s->ops = 0;
						s->state = STATE_OPEN;
						open_socket(SOCK_DGRAM, localhost, localport, NULL, s);
					} else {
						assert(mode == MODE_PROXY);
						prepare_reading_request(s);
						if (s->buffer.position != 0) {
							*done = 0;
						}
					}
				} else if (strncmp(s->http_status, "204", 3) == 0) {
					if (s->http_reader_position == s->buffer.position) {
						if (retry_count != 0) {
							retry_cutoff.tv_sec = 0;
							retry_cutoff.tv_usec = 0;
							retry_count = 0;
						}
						prepare_writing_request(s);
						s->ops = OP_WRITE;
					} else {
						handle_unexpected_response(s, __FILE__, __LINE__);
					}
				} else if (strncmp(s->http_status, "429", 3) == 0) {
					delay_retry(s);
				} else {
					handle_unexpected_response(s, __FILE__, __LINE__);
				}
			}
		}
	} else {
		handle_unexpected_response(s, __FILE__, __LINE__);
	}
}

static void update_token(struct http_reader *r, char **token, size_t *length) {
	assert(r != NULL);
	assert(token != NULL);
	assert(length != NULL);
	if (*token == NULL) {
		*token = r->result_token;
		*length = r->result_length;
	} else if (r->result_token != NULL) {
		assert(&(*token)[*length] == r->result_token);
		assert(*length <= SIZE_MAX - r->result_length);
		*length += r->result_length;
	}
}

static void read_http(struct socket_desc *s) {
	struct http_reader *r;
	assert(s != NULL);
	assert(s->buffer.data != NULL);
	assert(s->http_reader_position <= s->buffer.position);
	assert(!s->http_error);
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
				assert(s->http_header_name != NULL);
				if ((s->http_header_name_length == 8)
					&& (strncasecmp(s->http_header_name, "Location", 8) == 0))
				{
					if (s->http_location == NULL) {
						s->http_location = s->http_header_value;
						s->http_location_length = s->http_header_value_length;
					} else {
						s->http_error = 1;
					}
				} else if ((s->http_header_name_length == 11)
					&& (strncasecmp(s->http_header_name, "Retry-After", 11) == 0))
				{
					if (s->http_retry_after == NULL) {
						s->http_retry_after = s->http_header_value;
						s->http_retry_after_length = s->http_header_value_length;
					} else {
						s->http_error = 1;
					}
				}
			}
			s->http_header_name = NULL;
			s->http_header_value = NULL;
			break;
		}
	} while ((s->http_reader_position != s->buffer.position)
		&& (r->state != HTTP_READER_STATE_DONE)
		&& (r->state != HTTP_READER_STATE_ERROR)
		&& !s->http_error);
}

static void handle_buffer(struct socket_desc *s) {
	int done;
	assert(s != NULL);
	do {
		read_http(s);
		if (s->http_reader.state == HTTP_READER_STATE_DONE) {
			if (s->state == STATE_READING_RESPONSE) {
				handle_response(s, &done);
			} else {
				handle_request(s, &done);
			}
		} else if ((s->http_reader.state == HTTP_READER_STATE_ERROR) || s->http_error
			|| (s->buffer.position == s->buffer.limit))
		{
			if (s->state == STATE_READING_RESPONSE) {
				handle_unexpected_response(s, __FILE__, __LINE__);
			} else {
				assert(s->state == STATE_READING_REQUEST);
				handle_unexpected_request(s, __FILE__, __LINE__);
			}
			done = 1;
		}
	} while (!done);
}

static void read_dgram_socket(struct socket_desc *s) {
	struct buffer *b; ssize_t n;
	assert(s != NULL);
	assert(s->type == SOCK_DGRAM);
	assert(s->state == STATE_RELAYING);
	assert(s->peer != NULL);
	assert(s->peer->state == STATE_RELAYING);
	b = &s->buffer;
	assert(b->data != NULL);
	assert(b->position == 0);
	assert(b->limit > 2);
	do {
		n = recv(s->fd, &b->data[2], b->limit - 2, 0);
	} while ((n == -1) && (errno == EINTR));
	if (n > 0) {
		if (n <= 0xffff) {
			b->data[0] = (char)(n & 0xff);
			b->data[1] = (char)((n >> 8) & 0xff);
			b->position = 2 + n;
			flip_buffer(b);
			exclude(&s->ops, OP_READ);
			include(&s->peer->ops, OP_WRITE);
		} else {
			log_dgram_error(INFO_DROPPING_DATAGRAM,
				s->host, s->port, n, __FILE__, __LINE__);
		}
	}
}

static void handle_read_failure(struct socket_desc *s, int error) {
	assert(s != NULL);
	if ((s->state == STATE_READING_RESPONSE)
		|| (s->state == STATE_READING_REQUEST))
	{
		if (s->ssl != NULL) {
			log_ssl_socket_error(INFO_CONNECTION_FAILURE,
				s->host, s->port, error, __FILE__, __LINE__);
		} else {
			log_socket_error(INFO_CONNECTION_FAILURE,
				s->host, s->port, error, __FILE__, __LINE__);
		}
		if (mode == MODE_CLIENT) {
			assert(s->peer != NULL);
			assert(s->peer->state == STATE_OPEN);
			if (s->peer->ssl != NULL) {
				shutdown_ssl(s->peer);
			} else {
				close_socket(s->peer);
			}
		} else {
			assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
				|| (mode == MODE_PROXY));
			assert(s->peer == NULL);
			if (s->state == STATE_READING_RESPONSE) {
				assert(listener_count > 0);
				listener_count--;
			}
		}
		close_socket(s);
	} else {
		assert(s->state == STATE_RELAYING);
		assert(s->peer != NULL);
		assert(s->peer->state == STATE_RELAYING);
		if (!s->write_failed && !s->peer->read_failed) {
			if (s->peer->ssl != NULL) {
				shutdown_ssl(s->peer);
				close_socket(s);
			} else {
				shutdown(s->peer->fd, SHUT_WR);
				exclude(&s->ops, OP_READ);
				s->read_failed = 1;
			}
		} else {
			if (s->peer->ssl != NULL) {
				shutdown_ssl(s->peer);
			} else {
				close_socket(s->peer);
			}
			close_socket(s);
		}
	}
}

static void handle_read(struct socket_desc *s, struct buffer *b) {
	assert(s != NULL);
	assert(b != NULL);
	if ((s->state == STATE_READING_RESPONSE)
		|| (s->state == STATE_READING_REQUEST))
	{
		handle_buffer(s);
	} else {
		assert(s->state == STATE_RELAYING);
		assert(s->peer != NULL);
		assert(s->peer->state == STATE_RELAYING);
		if (s->peer->type == SOCK_STREAM) {
			flip_buffer(b);
			exclude(&s->ops, OP_READ);
			include(&s->peer->ops, OP_WRITE);
		} else {
			handle_dgram_buffer(s);
		}
	}
}

static void read_stream_socket(struct socket_desc *s) {
	struct buffer *b; ssize_t n;
	assert(s != NULL);
	b = &s->buffer;
	assert(b->data != NULL);
	assert(b->position < b->limit);
	do {
		n = recv(s->fd, &b->data[b->position], b->limit - b->position, 0);
	} while ((n == -1) && (errno == EINTR));
	if (n > 0) {
		b->position += n;
		handle_read(s, b);
	} else if ((n == 0) ||
		((n == -1) && (errno != EAGAIN) && (errno != EWOULDBLOCK)))
	{
		handle_read_failure(s, n == 0? 0: errno);
	} else {
		assert((n == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)));
	}
}

static void handle_client_initiated_renegotiation(struct socket_desc *s) {
	assert(mode == MODE_CLIENT);
	assert(s != NULL);
	assert(s->ssl != NULL);
	assert(s->ssl_handshake_count > 1);
	assert(strcmp(s->host, localhost) == 0);
	assert(s->port == localport);
	assert(s->peer != NULL);
	assert(s->peer->state != STATE_CLOSED);
	log_ssl_socket_error(INFO_CLIENT_INITIATED_RENEGOTIATION,
		s->host, s->port, SSL_ERROR_SSL, __FILE__, __LINE__);
	if (s->peer->ssl != NULL) {
		shutdown_ssl(s->peer);
	} else {
		close_socket(s->peer);
	}
	close_socket(s);
}

static void read_ssl_socket(struct socket_desc *s) {
	int r; struct buffer *b;
	assert(s != NULL);
	assert(s->ssl != NULL);
	assert(!s->ssl_handshake);
	b = &s->buffer;
	assert(b->data != NULL);
	assert(b->position < b->limit);
	r = SSL_read(s->ssl, &b->data[b->position], b->limit - b->position);
	if ((s->ssl_handshake_count > 1) && (mode == MODE_CLIENT)
		&& (strcmp(s->host, localhost) == 0) && (s->port == localport))
	{
		handle_client_initiated_renegotiation(s);
	} else if (r > 0) {
		b->position += r;
		handle_read(s, b);
	} else {
		r = SSL_get_error(s->ssl, r);
		if (r == SSL_ERROR_WANT_WRITE) {
			prepare_ssl_handshake(s);
			s->ops = OP_WRITE;
		} else if (r != SSL_ERROR_WANT_READ) {
			handle_read_failure(s, r);
		}
	}
}

static void write_dgram_socket(struct socket_desc *s) {
	struct buffer *b; ssize_t n;
	assert(s != NULL);
	assert(s->type == SOCK_DGRAM);
	assert(s->state == STATE_RELAYING);
	assert(s->peer != NULL);
	assert(s->peer->state == STATE_RELAYING);
	b = &s->peer->buffer;
	assert(b->data != NULL);
	assert(b->position == 0);
	assert(b->limit >= 2);
	assert(b->limit - 2 >= dgram_length(b->data));
	do {
		n = send(s->fd, &b->data[2], dgram_length(b->data), 0);
	} while ((n == -1) && (errno == EINTR));
	if ((n >= 0) ||
		((n == -1) && (errno != EAGAIN) && (errno != EWOULDBLOCK)))
	{
		b->position = 2 + dgram_length(b->data);
		compact_buffer(b);
		exclude(&s->ops, OP_WRITE);
		handle_dgram_buffer(s->peer);
	} else {
		assert((n == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)));
	}
}

static void handle_write_failure(struct socket_desc *s, int error) {
	assert(s != NULL);
	if ((s->state == STATE_WRITING_REQUEST)
		|| (s->state == STATE_WRITING_RESPONSE))
	{
		if (s->ssl != NULL) {
			log_ssl_socket_error(INFO_CONNECTION_FAILURE,
				s->host, s->port, error, __FILE__, __LINE__);
		} else {
			log_socket_error(INFO_CONNECTION_FAILURE,
				s->host, s->port, error, __FILE__, __LINE__);
		}
		if (mode == MODE_CLIENT) {
			assert(s->peer != NULL);
			assert(s->peer->state == STATE_OPEN);
			if (s->peer->ssl != NULL) {
				shutdown_ssl(s->peer);
			} else {
				close_socket(s->peer);
			}
		} else {
			assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
				|| (mode == MODE_PROXY));
			assert(s->peer == NULL);
			if (s->state == STATE_WRITING_REQUEST) {
				assert(listener_count > 0);
				listener_count--;
			}
		}
		close_socket(s);
	} else {
		assert(s->state == STATE_RELAYING);
		assert(s->peer != NULL);
		assert(s->peer->state == STATE_RELAYING);
		if (!s->read_failed && !s->peer->write_failed) {
			if (s->peer->ssl == NULL) {
				shutdown(s->peer->fd, SHUT_RD);
			}
			exclude(&s->ops, OP_WRITE);
			s->write_failed = 1;
		} else {
			if (s->peer->ssl != NULL) {
				shutdown_ssl(s->peer);
			} else {
				close_socket(s->peer);
			}
			close_socket(s);
		}
	}
}

static void handle_write(struct socket_desc *s, struct buffer *b) {
	assert(s != NULL);
	assert(b != NULL);
	if (b->position == b->limit) {
		clear_buffer(b);
		if (s->state == STATE_WRITING_REQUEST) {
			prepare_reading_response(s);
			s->ops = OP_READ;
		} else if (s->state == STATE_WRITING_RESPONSE) {
			assert(mode == MODE_PROXY);
			s->ops = 0;
			s->state = STATE_OPEN;
			open_socket(SOCK_STREAM, localhost, localport, NULL, s);
		} else {
			assert(s->state == STATE_RELAYING);
			assert(s->peer != NULL);
			assert(s->peer->state == STATE_RELAYING);
			exclude(&s->ops, OP_WRITE);
			include(&s->peer->ops, OP_READ);
		}
	} else {
		assert(b->position < b->limit);
	}
}

static void write_stream_socket(struct socket_desc *s) {
	struct buffer *b; ssize_t n;
	assert(s != NULL);
	if ((s->state == STATE_WRITING_REQUEST)
		|| (s->state == STATE_WRITING_RESPONSE))
	{
		b = &s->buffer;
	} else {
		assert(s->state == STATE_RELAYING);
		assert(s->peer != NULL);
		assert(s->peer->state == STATE_RELAYING);
		b = &s->peer->buffer;
	}
	assert(b->data != NULL);
	assert(b->position < b->limit);
	do {
		n = send(s->fd, &b->data[b->position], b->limit - b->position, 0);
	} while ((n == -1) && (errno == EINTR));
	if (n > 0) {
		b->position += n;
		handle_write(s, b);
	} else if ((n == 0) ||
		((n == -1) && (errno != EAGAIN) && (errno != EWOULDBLOCK)))
	{
		handle_write_failure(s, n == 0? 0: errno);
	} else {
		assert((n == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)));
	}
}

static void write_ssl_socket(struct socket_desc *s) {
	int r; struct buffer *b;
	assert(s != NULL);
	assert(s->ssl != NULL);
	assert(!s->ssl_handshake);
	if ((s->state == STATE_WRITING_REQUEST)
		|| (s->state == STATE_WRITING_RESPONSE))
	{
		b = &s->buffer;
	} else {
		assert(s->state == STATE_RELAYING);
		assert(s->peer != NULL);
		assert(s->peer->state == STATE_RELAYING);
		b = &s->peer->buffer;
	}
	assert(b->data != NULL);
	assert(b->position < b->limit);
	r = SSL_write(s->ssl, &b->data[b->position], b->limit - b->position);
	if ((s->ssl_handshake_count > 1) && (mode == MODE_CLIENT)
		&& (strcmp(s->host, localhost) == 0) && (s->port == localport))
	{
		handle_client_initiated_renegotiation(s);
	} else if (r > 0) {
		b->position += r;
		handle_write(s, b);
	} else {
		r = SSL_get_error(s->ssl, r);
		if (r == SSL_ERROR_WANT_READ) {
			prepare_ssl_handshake(s);
			s->ops = OP_READ;
		} else if (r != SSL_ERROR_WANT_WRITE) {
			handle_write_failure(s, r);
		}
	}
}

static void do_ssl_handshake(struct socket_desc *s) {
	int r; X509 *c;
	assert(s->ssl != NULL);
	assert(s->ssl_handshake);
	r = SSL_do_handshake(s->ssl);
	if (r == 1) {
		r = 0;
		if (certificate_verification) {
			c = SSL_get_peer_certificate(s->ssl);
			if (c != NULL) {
				r = tls_check_name(/* ctx: */ NULL, c, s->host);
				if (r != 0) {
					log_ssl_socket_error(INFO_CERTIFICATE_VERIFICATION_FAILURE,
						s->host, s->port, SSL_ERROR_SSL, __FILE__, __LINE__);
				}
				X509_free(c);
			} else {
				r = -1;
				log_ssl_socket_error(INFO_CERTIFICATE_VERIFICATION_FAILURE,
					s->host, s->port, SSL_ERROR_SSL, __FILE__, __LINE__);
			}
		}
		if (r == 0) {
			if (s->ssl->s3 != NULL) {
				s->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
			}
			if (mode == MODE_CLIENT) {
				update_ssl_session(s->ssl, &yaler_ssl_session);
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
					|| (mode == MODE_PROXY));
				if (s->peer == NULL) {
					update_ssl_session(s->ssl, &yaler_ssl_session);
				} else {
					update_ssl_session(s->ssl, &local_ssl_session);
				}
			}
			if (s->peer != NULL) {
				assert(!s->peer->ssl_handshake);
				s->peer->ops = s->peer->ssl_handshake_stash;
			}
			s->ops = s->ssl_handshake_stash;
			s->ssl_handshake = 0;
		} else {
			if (s->peer != NULL) {
				if (s->peer->state != STATE_CLOSED) {
					if (s->peer->ssl != NULL) {
						assert(!s->peer->ssl_handshake);
						shutdown_ssl(s->peer);
					} else {
						close_socket(s->peer);
					}
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
					|| (mode == MODE_PROXY));
				if ((s->state == STATE_WRITING_REQUEST)
					|| (s->state == STATE_READING_RESPONSE))
				{
					assert(listener_count > 0);
					listener_count--;
				}
			}
			close_socket(s);
		}
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
			if (s->peer != NULL) {
				if (s->peer->state != STATE_CLOSED) {
					if (s->peer->ssl != NULL) {
						assert(!s->peer->ssl_handshake);
						shutdown_ssl(s->peer);
					} else {
						close_socket(s->peer);
					}
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
					|| (mode == MODE_PROXY));
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

static void init_ssl_client(struct socket_desc *s, SSL_SESSION *session) {
	int r;
	assert(s != NULL);
	assert(s->ssl == NULL);
	s->ssl = SSL_new(ssl_client_ctx);
	if (s->ssl != NULL) {
		SSL_set_connect_state(s->ssl);
		r = SSL_set_fd(s->ssl, s->fd);
		if (r == 1) {
			if (session != NULL) {
				r = SSL_set_session(s->ssl, session);
				if (r != 1) {
					assert(r == 0);
					log_ssl_error(ERROR_SSL, SSL_ERROR_SSL, __FILE__, __LINE__);
					exit(EXIT_FAILURE);
				}
			}
			SSL_set_app_data(s->ssl, s);
		} else {
			assert(r == 0);
			log_ssl_error(ERROR_SSL, SSL_ERROR_SSL, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		log_ssl_error(ERROR_SSL, SSL_ERROR_SSL, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void connect_socket(struct socket_desc *s,
	struct sockaddr *addr, socklen_t addr_len)
{
	int r;
	assert(s != NULL);
	assert(s->state == STATE_OPEN);
	assert(s->fd == -1);
	s->fd = socket(addr->sa_family, s->type, 0);
	if (s->fd != -1) {
		set_nonblocking(s->fd);
		if (s->type == SOCK_STREAM) {
			set_nodelay(s->fd);
		}
		r = connect(s->fd, addr, addr_len);
		if ((r == -1) && (errno != EINTR) && (errno != EINPROGRESS)) {
			log_socket_error(INFO_CONNECTION_FAILURE,
				s->host, s->port, errno, __FILE__, __LINE__);
			if (s->peer != NULL) {
				assert(s->peer->state == STATE_OPEN);
				if (s->peer->ssl != NULL) {
					shutdown_ssl(s->peer);
				} else {
					close_socket(s->peer);
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
					|| (mode == MODE_PROXY));
				assert(listener_count > 0);
				listener_count--;
			}
			close_socket(s);
		} else {
			assert((r == 0) ||
				((r == -1) && ((errno == EINTR) || (errno == EINPROGRESS))));
			if (mode == MODE_CLIENT) {
				prepare_writing_request(s);
				s->ops = OP_WRITE;
				if (yalerssl) {
					init_ssl_client(s, yaler_ssl_session);
					prepare_ssl_handshake(s);
				}
			} else {
				assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
					|| (mode == MODE_PROXY));
				if (s->peer == NULL) {
					prepare_writing_request(s);
					s->ops = OP_WRITE;
					if (yalerssl) {
						init_ssl_client(s, yaler_ssl_session);
						prepare_ssl_handshake(s);
					}
				} else {
					prepare_relaying(s);
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

static void accept_socket(struct socket_desc *s) {
	int fd; struct socket_desc *t;
	assert(buffer_size >= 0);
	assert((size_t)buffer_size <= SIZE_MAX - sizeof (struct socket_desc));
	assert(s != NULL);
	fd = accept(s->fd, NULL, NULL);
	if (fd != -1) {
		set_nonblocking(fd);
		if (s->type == SOCK_STREAM) {
			set_nodelay(fd);
		}
		t = alloc(sizeof (struct socket_desc) + buffer_size);
		t->next = NULL;
		t->peer = NULL;
		t->type = s->type;
		assert(sizeof t->host > HOST_MAX);
		assert(sizeof t->host == sizeof s->host);
		strncpy(t->host, s->host, sizeof t->host);
		t->host[sizeof t->host - 1] = 0;
		t->port = s->port;
		t->domain[0] = 0;
		t->fd = fd;
		t->ops = 0;
		t->state = STATE_OPEN;
		t->read_failed = 0;
		t->write_failed = 0;
		t->stamp = now;
		t->q = NULL;
		t->ssl = NULL;
		t->ssl_handshake = 0;
		t->ssl_handshake_count = 0;
		t->buffer.position = 0;
		t->buffer.limit = buffer_size;
		t->buffer.data = (char *)t + sizeof (struct socket_desc);
		t->dgram_drop_count = 0;
		register_socket(t);
		open_socket(SOCK_STREAM, yalerhost, yalerport, yalerdomain, t);
	} else if ((errno != EINTR) && (errno != EAGAIN) && (errno != EWOULDBLOCK)
		&& (errno != ETIMEDOUT) && (errno != ECONNABORTED) && (errno != EPROTO)
		&& (errno != EHOSTDOWN) && (errno != EHOSTUNREACH) && (errno != ENONET)
		&& (errno != ENETDOWN) && (errno != ENETUNREACH))
	{
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void bind_socket(struct socket_desc *s,
	struct sockaddr *addr, socklen_t addr_len)
{
	int r;
	assert(s != NULL);
	assert(s->fd == -1);
	s->fd = socket(addr->sa_family, s->type, 0);
	if (s->fd != -1) {
		set_nonblocking(s->fd);
		set_reuseaddr(s->fd);
		r = bind(s->fd, addr, addr_len);
		if (r == 0) {
			r = listen(s->fd, 64);
			if (r == 0) {
				s->ops = OP_ACCEPT;
			} else {
				assert(r == -1);
				log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		} else {
			assert(r == -1);
			log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void handle_dns_failure(struct dns_ctx *c, struct socket_desc *s) {
	assert(s != NULL);
	assert(s->state == STATE_OPEN);
	assert((s->ops == OP_BIND) || (s->ops == OP_CONNECT));
	log_dns_error(INFO_DNS_FAILURE, s->host, dns_status(c), __FILE__, __LINE__);
	if (s->peer != NULL) {
		assert(s->peer->state == STATE_OPEN);
		if (s->peer->ssl != NULL) {
			shutdown_ssl(s->peer);
		} else {
			close_socket(s->peer);
		}
	} else {
		assert(listener_count > 0);
		listener_count--;
	}
	close_socket(s);
}

static void handle_dns_a6_callback(
	struct dns_ctx *c, struct dns_rr_a6 *r, void *d)
{
	struct socket_desc *s; struct sockaddr_in6 sa;
	assert(d != NULL);
	s = (struct socket_desc *)d;
	s->q = NULL;
	if ((r != NULL) && (r->dnsa6_nrr > 0)) {
		assert(r->dnsa6_addr != NULL);
		memset(&sa, 0, sizeof sa);
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(s->port);
		sa.sin6_addr = r->dnsa6_addr[0];
		if (s->ops == OP_BIND) {
			bind_socket(s, (struct sockaddr *)&sa, sizeof sa);
		} else {
			assert(s->ops == OP_CONNECT);
			connect_socket(s, (struct sockaddr *)&sa, sizeof sa);
		}
	} else {
		handle_dns_failure(c, s);
	}
	if (r != NULL) {
		free(r);
	}
}

static void handle_dns_a4_callback(
	struct dns_ctx *c, struct dns_rr_a4 *r, void *d)
{
	struct socket_desc *s; struct sockaddr_in sa;
	(void)c;
	assert(d != NULL);
	s = (struct socket_desc *)d;
	s->q = NULL;
	if ((r != NULL) && (r->dnsa4_nrr > 0)) {
		assert(r->dnsa4_addr != NULL);
		memset(&sa, 0, sizeof sa);
		sa.sin_family = AF_INET;
		sa.sin_port = htons(s->port);
		sa.sin_addr = r->dnsa4_addr[0];
		if (s->ops == OP_BIND) {
			bind_socket(s, (struct sockaddr *)&sa, sizeof sa);
		} else {
			assert(s->ops == OP_CONNECT);
			connect_socket(s, (struct sockaddr *)&sa, sizeof sa);
		}
	} else {
		assert((s->ops == OP_BIND) || (s->ops == OP_CONNECT));
		s->q = dns_submit_a6(NULL, s->host, 0, handle_dns_a6_callback, s);
		if (s->q == NULL) {
			log_dns_error(ERROR_DNS, s->host, dns_status(NULL), __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	}
	if (r != NULL) {
		free(r);
	}
}

static void open_socket(
	int type, char *host, int port, char *domain, struct socket_desc *peer)
{
	int r; struct socket_desc *s;
	struct in_addr a; struct sockaddr_in sa;
	struct in6_addr a6; struct sockaddr_in6 sa6;
	assert(buffer_size >= 0);
	assert((size_t)buffer_size <= SIZE_MAX - sizeof (struct socket_desc));
	assert((type == SOCK_DGRAM) || (type == SOCK_STREAM));
	assert((host != NULL)
		&& (strlen(host) <= HOST_MAX));
	assert((domain == NULL)
		|| (strlen(domain) <= DOMAIN_MAX));
	s = alloc(sizeof (struct socket_desc) + buffer_size);
	s->next = NULL;
	s->peer = peer;
	s->type = type;
	assert(sizeof s->host > HOST_MAX);
	strncpy(s->host, host, sizeof s->host);
	s->host[sizeof s->host - 1] = 0;
	s->port = port;
	assert(sizeof s->domain > DOMAIN_MAX);
	if (domain == NULL) {
		s->domain[0] = 0;
	} else {
		strncpy(s->domain, domain, sizeof s->domain);
		s->domain[sizeof s->domain - 1] = 0;
	}
	s->fd = -1;
	s->ops = OP_CONNECT;
	s->state = STATE_OPEN;
	s->read_failed = 0;
	s->write_failed = 0;
	s->stamp = now;
	s->q = NULL;
	s->ssl = NULL;
	s->ssl_handshake = 0;
	s->ssl_handshake_count = 0;
	s->buffer.position = 0;
	s->buffer.limit = buffer_size;
	s->buffer.data = (char *)s + sizeof (struct socket_desc);
	s->dgram_drop_count = 0;
	if (peer != NULL) {
		assert(peer->peer == NULL);
		peer->peer = s;
	}
	register_socket(s);
	r = dns_pton(AF_INET, host, &a);
	if (r > 0) {
		memset(&sa, 0, sizeof sa);
		sa.sin_family = AF_INET;
		sa.sin_port = htons(s->port);
		sa.sin_addr = a;
		connect_socket(s, (struct sockaddr *)&sa, sizeof sa);
	} else if (r == 0) {
		r = dns_pton(AF_INET6, host, &a6);
		if (r > 0) {
			memset(&sa6, 0, sizeof sa6);
			sa6.sin6_family = AF_INET6;
			sa6.sin6_port = htons(s->port);
			sa6.sin6_addr = a6;
			connect_socket(s, (struct sockaddr *)&sa6, sizeof sa6);
		} else if (r == 0) {
			s->q = dns_submit_a4(NULL, host, 0, handle_dns_a4_callback, s);
			if (s->q == NULL) {
				log_dns_error(ERROR_DNS, host, dns_status(NULL), __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		} else {
			log_dns_error(ERROR_DNS, host, dns_status(NULL), __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		log_dns_error(ERROR_DNS, host, dns_status(NULL), __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void open_server_socket(int type, char *host, int port) {
	int r; struct socket_desc *s;
	struct in_addr a; struct sockaddr_in sa;
	struct in6_addr a6; struct sockaddr_in6 sa6;
	assert((type == SOCK_DGRAM) || (type == SOCK_STREAM));
	assert((host != NULL)
		&& (strlen(host) <= HOST_MAX));
	s = alloc(sizeof (struct socket_desc));
	s->next = NULL;
	s->peer = NULL;
	s->type = type;
	assert(sizeof s->host > HOST_MAX);
	strncpy(s->host, host, sizeof s->host);
	s->host[sizeof s->host - 1] = 0;
	s->port = port;
	assert(sizeof s->domain > DOMAIN_MAX);
	s->domain[0] = 0;
	s->fd = -1;
	s->ops = OP_BIND;
	s->state = STATE_OPEN;
	s->read_failed = 0;
	s->write_failed = 0;
	s->stamp = now;
	s->q = NULL;
	s->ssl = NULL;
	s->ssl_handshake = 0;
	s->ssl_handshake_count = 0;
	s->buffer.position = 0;
	s->buffer.limit = 0;
	s->buffer.data = NULL;
	s->dgram_drop_count = 0;
	register_socket(s);
	r = dns_pton(AF_INET, host, &a);
	if (r > 0) {
		memset(&sa, 0, sizeof sa);
		sa.sin_family = AF_INET;
		sa.sin_port = htons(s->port);
		sa.sin_addr = a;
		bind_socket(s, (struct sockaddr *)&sa, sizeof sa);
	} else if (r == 0) {
		r = dns_pton(AF_INET6, host, &a6);
		if (r > 0) {
			memset(&sa6, 0, sizeof sa6);
			sa6.sin6_family = AF_INET6;
			sa6.sin6_port = htons(s->port);
			sa6.sin6_addr = a6;
			bind_socket(s, (struct sockaddr *)&sa6, sizeof sa6);
		} else if (r == 0) {
			s->q = dns_submit_a4(NULL, host, 0, handle_dns_a4_callback, s);
			if (s->q == NULL) {
				log_dns_error(ERROR_DNS, host, dns_status(NULL), __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		} else {
			log_dns_error(ERROR_DNS, host, dns_status(NULL), __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
	} else {
		log_dns_error(ERROR_DNS, host, dns_status(NULL), __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
}

static void collect_garbage() {
	struct socket_desc *s, *p, *x;
	p = NULL;
	s = sockets;
	while (s != NULL) {
		if (s->state == STATE_CLOSED) {
			x = s;
			s = s->next;
			if (p == NULL) {
				sockets = s;
			} else {
				p->next = s;
			}
			free(x);
		} else {
			p = s;
			s = s->next;
		}
	}
}

static void close_dns() {
	struct socket_desc *s;
	s = sockets;
	while (s != NULL) {
		if (s->q != NULL) {
			dns_cancel(NULL, s->q);
			s->q = NULL;
			handle_dns_failure(NULL, s);
		}
		s = s->next;
	}
	dns_close(NULL);
}

static void test_socket_fds(fd_set *readfds, fd_set *writefds) {
	struct socket_desc *s;
	assert(readfds != NULL);
	assert(writefds != NULL);
	s = sockets;
	while (s != NULL) {
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
				} else if (s->ssl != NULL) {
					read_ssl_socket(s);
				} else if (s->type == SOCK_STREAM) {
					read_stream_socket(s);
				} else {
					assert(s->type == SOCK_DGRAM);
					read_dgram_socket(s);
				}
			}
			if (contains(s->ops, OP_WRITE) && FD_ISSET(s->fd, writefds)) {
				s->stamp = now;
				if (s->ssl_handshake) {
					do_ssl_handshake(s);
				} else if (s->ssl != NULL) {
					if (s->state == STATE_CLOSING) {
						shutdown_ssl(s);
					} else {
						write_ssl_socket(s);
					}
				} else if (s->type == SOCK_STREAM) {
					write_stream_socket(s);
				} else {
					assert(s->type == SOCK_DGRAM);
					write_dgram_socket(s);
				}
			}
			if (contains(s->ops, OP_READ) || contains(s->ops, OP_WRITE)) {
				if ((now.tv_sec < s->stamp.tv_sec)
					|| ((now.tv_sec == s->stamp.tv_sec)
						&& (now.tv_usec < s->stamp.tv_usec)))
				{
					s->stamp = now;
				} else if ((now.tv_sec >= max_idle_time)
					&& ((now.tv_sec - max_idle_time > s->stamp.tv_sec)
						|| ((now.tv_sec - max_idle_time == s->stamp.tv_sec)
							&& (now.tv_usec > s->stamp.tv_usec))))
				{
					eprintf("%s:%s:%d@%s:%d\n", INFO_CONNECTION_TIMEOUT,
						s->host, s->port, __FILE__, __LINE__);
					if (s->peer != NULL) {
						if (s->peer->state != STATE_CLOSED) {
							if (s->peer->ssl != NULL) {
								shutdown_ssl(s->peer);
							} else {
								close_socket(s->peer);
							}
						}
					} else {
						assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
							|| (mode == MODE_PROXY));
						if ((s->state == STATE_WRITING_REQUEST)
							|| (s->state == STATE_READING_RESPONSE))
						{
							assert(listener_count > 0);
							listener_count--;
						}
					}
					if ((s->ssl != NULL) && (s->state != STATE_CLOSING)) {
						shutdown_ssl(s);
					} else {
						close_socket(s);
					}
				}
			}
		}
		s = s->next;
	}
}

static void set_socket_fds(
	fd_set *readfds, fd_set *writefds, int *maxfd, int *timeout)
{
	int op_read, op_write, t; struct socket_desc *s; struct timeval dt;
	assert(readfds != NULL);
	assert(writefds != NULL);
	assert(maxfd != NULL);
	assert(timeout != NULL);
	*timeout = -1;
	s = sockets;
	while (s != NULL) {
		if (contains(s->ops, OP_ACCEPT)) {
			assert(listener_count == 1);
			assert(socket_count >= 1);
			assert(socket_count <= max_sockets);
			if (socket_count <= max_sockets - 2) {
				assert(s->fd >= 0);
				assert(s->fd < FD_SETSIZE);
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
					assert(s->fd >= 0);
					assert(s->fd < FD_SETSIZE);
					FD_SET(s->fd, readfds);
				}
				if (op_write) {
					assert(s->fd >= 0);
					assert(s->fd < FD_SETSIZE);
					FD_SET(s->fd, writefds);
				}
				if (s->fd > *maxfd) {
					*maxfd = s->fd;
				}
				if ((now.tv_sec < s->stamp.tv_sec)
					|| ((now.tv_sec == s->stamp.tv_sec)
						&& (now.tv_usec < s->stamp.tv_usec)))
				{
					s->stamp = now;
				} else {
					if (now.tv_usec >= s->stamp.tv_usec) {
						dt.tv_sec = now.tv_sec - s->stamp.tv_sec;
						dt.tv_usec = now.tv_usec - s->stamp.tv_usec;
					} else {
						dt.tv_sec = now.tv_sec - s->stamp.tv_sec - 1;
						dt.tv_usec = 1000000 - (s->stamp.tv_usec - now.tv_usec);
					}
					assert(max_idle_time < INT_MAX);
					if (dt.tv_sec < max_idle_time + 1) {
						if (dt.tv_usec == 0) {
							t = max_idle_time - dt.tv_sec + 1;
						} else {
							t = max_idle_time - dt.tv_sec;
						}
						if ((*timeout == -1) || (t < *timeout)) {
							*timeout = t;
						}
					} else {
						*timeout = 0;
					}
				}
			}
		}
		s = s->next;
	}
}

static void run_tunnel() {
	int d, r, t, dnsfd, maxfd; fd_set readfds, writefds;
	struct timeval *timeout, tv_timeout, tv;
	get_time(&now);
	init_seed(now.tv_sec);
	init_signal_handling();
	init_dns(&dnsfd);
	if (localssl || yalerssl) {
		init_ssl_client_ctx(&ssl_client_ctx);
	}
	while (1) {
		get_time(&now);
		timeout = NULL;
		maxfd = -1;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		assert(0 <= retry_count);
		assert(0 <= listener_count);
		assert(listener_count <= min_listeners);
		assert(listener_count <= socket_count);
		assert(socket_count <= max_sockets);
		d = listener_delta();
		if (d != 0) {
			if ((now.tv_sec < retry_cutoff.tv_sec)
				|| ((now.tv_sec == retry_cutoff.tv_sec)
					&& (now.tv_usec < retry_cutoff.tv_usec)))
			{
				timeout = &tv_timeout;
				if (retry_cutoff.tv_usec >= now.tv_usec) {
					timeout->tv_sec = retry_cutoff.tv_sec - now.tv_sec;
					timeout->tv_usec = retry_cutoff.tv_usec - now.tv_usec;
				} else {
					timeout->tv_sec = retry_cutoff.tv_sec - now.tv_sec - 1;
					timeout->tv_usec = 1000000 - (now.tv_usec - retry_cutoff.tv_usec);
				}
			} else {
				t = msec_delay(retry_count);
				if (t >= 0) {
					t = randomized(t);
					tv.tv_sec = t / 1000;
					tv.tv_usec = (t % 1000) * 1000;
					retry_cutoff.tv_sec = now.tv_sec + tv.tv_sec;
					if (tv.tv_usec < 1000000 - now.tv_usec) {
						retry_cutoff.tv_usec = now.tv_usec + tv.tv_usec;
					} else {
						retry_cutoff.tv_sec++;
						retry_cutoff.tv_usec = tv.tv_usec - (1000000 - now.tv_usec);
					}
					assert(retry_count < INT_MAX);
					retry_count++;
				} else {
					retry_cutoff.tv_sec = 0;
					retry_cutoff.tv_usec = 0;
					retry_count = 0;
				}
				do {
					if (mode == MODE_CLIENT) {
						open_server_socket(SOCK_STREAM, localhost, localport);
					} else {
						assert((mode == MODE_SERVER) || (mode == MODE_DSERVER)
							|| (mode == MODE_PROXY));
						open_socket(SOCK_STREAM, yalerhost, yalerport, yalerdomain, NULL);
					}
					listener_count++;
					d--;
				} while (d != 0);
			}
		}
		assert((timeout == NULL) == (d == 0));
		t = dns_timeouts(NULL, -1, now.tv_sec);
		if (t >= 0) {
			if (timeout == NULL) {
				timeout = &tv_timeout;
				timeout->tv_sec = t;
				timeout->tv_usec = 0;
			} else if (t <= timeout->tv_sec) {
				timeout->tv_sec = t;
				timeout->tv_usec = 0;
			}
			assert(dnsfd >= 0);
			assert(dnsfd < FD_SETSIZE);
			FD_SET(dnsfd, &readfds);
			if (dnsfd > maxfd) {
				maxfd = dnsfd;
			}
		} else {
			assert(t == -1);
			if ((timeout == NULL) && (listener_delta() != 0)) {
				timeout = &tv_timeout;
				timeout->tv_sec = 0;
				timeout->tv_usec = 0;
			}
		}
		set_socket_fds(&readfds, &writefds, &maxfd, &t);
		if (t >= 0) {
			if (timeout == NULL) {
				timeout = &tv_timeout;
				timeout->tv_sec = t;
				timeout->tv_usec = 0;
			} else if (t <= timeout->tv_sec) {
				timeout->tv_sec = t;
				timeout->tv_usec = 0;
			}
		}
		if ((timeout != NULL)
			&& ((timeout->tv_sec > TIMEOUT_MAX_SEC)
				|| ((timeout->tv_sec == TIMEOUT_MAX_SEC)
					&& (timeout->tv_usec > 0))))
		{
			timeout->tv_sec = TIMEOUT_MAX_SEC;
			timeout->tv_usec = 0;
		}
		assert(maxfd >= -1);
		assert(maxfd < FD_SETSIZE);
		assert((timeout != NULL)
			|| ((mode == MODE_CLIENT) && (socket_count == listener_count)));
		r = select(maxfd + 1, &readfds, &writefds, NULL, timeout);
		if (r >= 0) {
			get_time(&now);
			if (FD_ISSET(dnsfd, &readfds)) {
				dns_ioevent(NULL, now.tv_sec);
			}
			if (dns_status(NULL) != DNS_E_NOERROR) {
				close_dns();
				init_dns(&dnsfd);
			}
			test_socket_fds(&readfds, &writefds);
			collect_garbage();
		} else {
			assert(r == -1);
			if (errno != EINTR) {
				log_error(ERROR_SYSCALL, errno, __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
		}
	}
}

static void print_usage() {
	fprintf(stderr, "YalerTunnel " VERSION "\n"
		"Usage: yalertunnel (client | server | proxy)"
		" [tls:]<local host>[:<port>]"
		" [tls:]<yaler host>[:<port>] <yaler domain>"
		" [--secret-key <secret-key>]"
		" [--ca-file <ca-file>]"
		" [--no-certificate-verification]\n");
}

static int is_valid_domain(char *d) {
	size_t i; char x;
	assert(d != NULL);
	i = 0;
	x = d[i];
	while ((x != '\0') && (
		(('A' <= x) && (x <= 'Z')) ||
		(('a' <= x) && (x <= 'z')) ||
		(('0' <= x) && (x <= '9')) ||
		(x == '-') || (x == '.') || (x == '_') || (x == '~') ||
		(x == '%') || (x == '!') || (x == '$') || (x == '&') ||
		(x == '\'')|| (x == '(') || (x == ')') || (x == '*') ||
		(x == '+') || (x == ',') || (x == ';') || (x == '=')))
	{
		i++;
		x = d[i];
	}
	return (x == '\0') && (0 < i) && (i <= DOMAIN_MAX) && (
		(i != 12)
		|| ((d[0] != 'R') && (d[0] != 'r'))
		|| ((d[1] != 'E') && (d[1] != 'e'))
		|| ((d[2] != 'L') && (d[2] != 'l'))
		|| ((d[3] != 'A') && (d[3] != 'a'))
		|| ((d[4] != 'Y') && (d[4] != 'y'))
		|| (d[5] != '_')
		|| ((d[6] != 'D') && (d[6] != 'd'))
		|| ((d[7] != 'O') && (d[7] != 'o'))
		|| ((d[8] != 'M') && (d[8] != 'm'))
		|| ((d[9] != 'A') && (d[9] != 'a'))
		|| ((d[10] != 'I') && (d[10] != 'i'))
		|| ((d[11] != 'N') && (d[11] != 'n')));
}

static void split_endpoint(char *s, char **host, int *port, int *ssl) {
	char *t;
	assert(s != NULL);
	assert(host != NULL);
	assert(port != NULL);
	assert(ssl != NULL);
	if ((strstr(s, "tls:") == s) || (strstr(s, "ssl:") == s)) {
		s += 4;
		*ssl = 1;
	} else {
		*ssl = 0;
	}
	t = strrchr(s, ':');
	if (t != NULL) {
		*t = 0;
		*host = s;
		*port = atoi(t + 1);
	} else {
		*host = s;
		*port = *ssl? 443: 80;
	}
}

int main(int argc, char *argv[]) {
	int i;
	if (argc >= 5) {
		if ((strcmp(argv[1], "client") == 0)
			|| (strcmp(argv[1], "server") == 0)
			|| (strcmp(argv[1], "dgram-server") == 0)
			|| (strcmp(argv[1], "proxy") == 0))
		{
			mode = argv[1][0];
			split_endpoint(argv[2], &localhost, &localport, &localssl);
			split_endpoint(argv[3], &yalerhost, &yalerport, &yalerssl);
			yalerdomain = argv[4];
			i = 5;
			while ((i != argc) && (i != -1)) {
				if ((strcmp(argv[i], "--no-certificate-verification") == 0)
					|| (strcmp(argv[i], "-no-certificate-verification") == 0))
				{
					certificate_verification = 0;
					i++;
				} else if (i + 1 != argc) {
					if ((strcmp(argv[i], "--secret-key") == 0)
						|| (strcmp(argv[i], "-secret-key") == 0))
					{
						secret_key = argv[i + 1];
						i += 2;
					} else if ((strcmp(argv[i], "--ca-file") == 0)
						|| (strcmp(argv[i], "-ca-file") == 0))
					{
						ca_file = argv[i + 1];
						i += 2;
					} else if ((strcmp(argv[i], "--min-listeners") == 0)
						|| (strcmp(argv[i], "-min-listeners") == 0))
					{
						min_listeners = atoi(argv[i + 1]);
						i += 2;
					} else if ((strcmp(argv[i], "--max-sockets") == 0)
						|| (strcmp(argv[i], "-max-sockets") == 0))
					{
						max_sockets = atoi(argv[i + 1]);
						i += 2;
					} else if ((strcmp(argv[i], "--buffer-size") == 0)
						|| (strcmp(argv[i], "-buffer-size") == 0))
					{
						buffer_size = atoi(argv[i + 1]);
						i += 2;
					} else if ((strcmp(argv[i], "--relay-security") == 0)
						|| (strcmp(argv[i], "-relay-security") == 0))
					{
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
				&& (strlen(localhost) <= HOST_MAX)
				&& (strlen(yalerhost) <= HOST_MAX)
				&& is_valid_domain(yalerdomain)
				&& (min_listeners > 0)
				&& (max_sockets > min_listeners)
				&& (buffer_size > 2)
				&& ((size_t)buffer_size <= SIZE_MAX - sizeof (struct socket_desc)))
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
