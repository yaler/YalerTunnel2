/*
** Copyright (c) 2019, Yaler GmbH, Switzerland
** All rights reserved
*/

#ifndef TLS_VERIFY_H
#define TLS_VERIFY_H

#include <openssl/ssl.h>

struct tls { int _; };

int tls_check_name(struct tls *ctx, X509 *cert, const char *name);

#endif
