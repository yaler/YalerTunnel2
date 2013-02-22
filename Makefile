default: http_reader_test yalertunnel

CC = gcc
CFLAGS = -ansi -pedantic -Wall -Wextra -Wc++-compat -g \
	-O3 -fno-strict-overflow -fno-delete-null-pointer-checks -fno-strict-aliasing

CC-OBJECT = $(CC) $(CFLAGS) -c $(filter-out %.h, $^)
CC-EXECUTABLE = $(CC) $(CFLAGS) -o $@ $(filter-out %.h, $^)

udns/libudns.a:
	make -C udns libudns.a

http_reader.o: http_reader.c http_reader.h
	$(CC-OBJECT)

http_reader_test: http_reader_test.c http_reader.o
	$(CC-EXECUTABLE)

yalertunnel: yalertunnel.c udns/libudns.a http_reader.o
	$(CC-EXECUTABLE) -lssl -lcrypto

clean:
	(cd udns && make clean)
	rm -f yalertunnel
	rm -f http_reader_test
	rm -f http_reader.o

distclean:
	(cd udns && make distclean)
	rm -f yalertunnel
	rm -f http_reader_test
	rm -f http_reader.o

.PHONY: default clean distclean
