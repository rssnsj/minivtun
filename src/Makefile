#
# Copyright (c) 2015 Justin Liu
# Author: Justin Liu <rssnsj@gmail.com>
# https://github.com/rssnsj/minivtun
#

CC ?= gcc
CFLAGS += -Wall
HEADERS = minivtun.h library.h list.h jhash.h

lnf-emulator: minivtun.o library.o server.o client.o
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

install: lnf-emulator
	cp -f lnf-emulator /usr/sbin/

clean:
	rm -f lnf-emulator *.o

