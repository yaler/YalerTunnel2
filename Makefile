default: yalertunnel

SRC = \
	http_reader.c \
	tls/tls_verify.c \
	udns/udns_bl.c \
	udns/udns_codes.c \
	udns/udns_dn.c \
	udns/udns_dntosp.c \
	udns/udns_init.c \
	udns/udns_jran.c \
	udns/udns_misc.c \
	udns/udns_parse.c \
	udns/udns_resolver.c \
	udns/udns_rr_a.c \
	udns/udns_rr_mx.c \
	udns/udns_rr_naptr.c \
	udns/udns_rr_ptr.c \
	udns/udns_rr_srv.c \
	udns/udns_rr_txt.c \
	udns/udns_XtoX.c \
	yalertunnel.c

OBJ = $(SRC:.c=.o)

DEP = $(SRC:.c=.d)
-include $(DEP)

CPPFLAGS += -MMD -MP

CFLAGS += -std=c99 -pedantic -pedantic-errors -g -O3 \
	-fno-strict-overflow -fno-strict-aliasing \
	-D_BSD_SOURCE \
	-D_DEFAULT_SOURCE \
	-DHAVE_GETOPT \
	-DHAVE_INET_PTON_NTOP \
	-DHAVE_IPv6 \
	-DHAVE_POLL \
	-Werror -Wall -Wextra

ifneq ($(findstring clang, $(shell gcc --version)), clang)
	CFLAGS += -fno-delete-null-pointer-checks
endif

ifdef OPENSSLDIR
	CFLAGS += -I$(OPENSSLDIR)/include
	LDFLAGS += -L$(OPENSSLDIR)/lib
endif

LDLIBS += -lssl -lcrypto

yalertunnel: $(OBJ)

clean:
	rm -f yalertunnel $(OBJ) $(DEP)

.PHONY: clean
