#
# Copyright (c) 2015 Justin Liu
# Author: Justin Liu <rssnsj@gmail.com>
# https://github.com/rssnsj/minivtun
#

ifeq ($(PREFIX),)
PREFIX := $(shell [ -d /opt/local ] && echo /opt/local || echo /usr )
endif

CC ?= gcc
CFLAGS += -Wall -Wno-deprecated
HEADERS = minivtun.h library.h list.h jhash.h

lfn-emulator: minivtun.o library.o server.o client.o
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

install: lfn-emulator
	cp -f minivtun $(PREFIX)/sbin/

clean:
	rm -f lfn-emulator *.o

