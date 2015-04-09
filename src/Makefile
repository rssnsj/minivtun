#
# Copyright (c) 2015 Justin Liu
# Author: Justin Liu <rssnsj@gmail.com>
# https://github.com/rssnsj/network-feeds
#

CC ?= gcc
CFLAGS += -Wall -g
HEADERS = minivtun.h library.h list.h

minivtun: minivtun.o library.o server.o client.o
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

install: minivtun
	cp -f minivtun /usr/sbin/

clean:
	rm -f minivtun *.o

up:
	make clean
	rsync ../ root@w.rssn.cn:minivtun/ -av --exclude=rsync.sh
	rsync ../ root@192.168.5.56:minivtun/ -av --exclude=rsync.sh
	make
