default: http_reader_test yalertunnel

CC = gcc
CFLAGS = -ansi -pedantic -g -O3 \
	-Wall -Wextra -Wc++-compat -Wno-unknown-pragmas \
	-O3 -fno-strict-overflow -fno-strict-aliasing

ifeq (, $(findstring clang, $(shell gcc --version)))
	CFLAGS += -fno-delete-null-pointer-checks
endif

ifdef OPENSSLDIR
	CFLAGS += -I$(OPENSSLDIR)/include
	OPENSSLLIBS = $(OPENSSLDIR)/lib/libssl.a $(OPENSSLDIR)/lib/libcrypto.a
else
	OPENSSLLIBS = -lssl -lcrypto
endif

CC-OBJECT = $(CC) $(CFLAGS) -c $(filter-out %.h, $^)
CC-EXECUTABLE = $(CC) $(CFLAGS) -o $@ $(filter-out %.h, $^)

udns/libudns.a:
	make -C udns libudns.a

http_reader.o: http_reader.c http_reader.h
	$(CC-OBJECT)

http_reader_test: http_reader_test.c http_reader.o
	$(CC-EXECUTABLE)

yalertunnel: yalertunnel.c udns/libudns.a http_reader.o
	$(CC-EXECUTABLE) $(OPENSSLLIBS)

clean:
	(cd udns && make clean)
	rm -f yalertunnel
	rm -rf yalertunnel.dSYM
	rm -f http_reader_test
	rm -rf http_reader_test.dSYM
	rm -f http_reader.o

distclean:
	(cd udns && make distclean)
	rm -f yalertunnel
	rm -rf yalertunnel.dSYM
	rm -f http_reader_test
	rm -rf http_reader_test.dSYM
	rm -f http_reader.o

.PHONY: default clean distclean
