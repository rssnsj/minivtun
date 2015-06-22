#
# Copyright (c) 2015 Justin Liu
# Author: Justin Liu <rssnsj@gmail.com>
# https://github.com/rssnsj/minivtun
#

CC ?= gcc
CFLAGS += -Wall
HEADERS = minivtun.h library.h list.h jhash.h

lfn-emulator: minivtun.o library.o server.o client.o
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

install: lfn-emulator
	cp -f lfn-emulator /usr/sbin/

clean:
	rm -f lfn-emulator *.o

