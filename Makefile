#
#   Copyright (c) 2020 NTT corp. - All Rights Reserved
#
#   This file is part of opcount which is released under Software LICENSE
#   Agreement for Evaluation. See file LICENSE.pdf for full license details.
#

CC = gcc
CPP = /usr/bin/c++
CFLAGS = -I/usr/local/include/relic -I/usr/local/include
CPPFLAGS = -pthread  -fopenmp -Wall -march=native -O3 -maes -mrdseed -std=c++17 -DEMP_CIRCUIT_PATH=/usr/local/include/emp-tool/circuits/files/ -I../emp-sh2pc -I/usr/local/include -I/usr/include/x86_64-linux-gnu
CLIBS = -lrelic /usr/local/lib/librelic_s.a /usr/local/lib/librelic.so
CPPLIBS = -rdynamic -lssl -lcrypto -lboost_system -lgmp /usr/local/lib/libemp-tool.so -Wl,-rpath,/usr/local/lib

all:  clean protocol_bin

ecdsa.o:
	$(CC) $(CFLAGS) -c ecdsa/ecdsa.c -lrelic -o ecdsa.o

protocol.o:  ecdsa.o
	$(CPP) $(CFLAGS) $(CPPFLAGS) -c protocol.cpp -lrelic -o protocol.o

protocol_bin: protocol.o ecdsa.o
	$(CPP) $(CPPFLAGS) $(CFLAGS) protocol.o ecdsa.o $(CPPLIBS) $(CLIBS) -o protocol_bin

get-emp-toolkit:
	cd external && python emp-install.py -install -tool -sh2pc -ot

get-relic:
	git clone https://github.com/relic-toolkit/relic.git
	cd relic && git checkout `git rev-list -n 1 --first-parent --before="2020-05-01 12:00" master`
	cd relic && mkdir build && cd build && cmake --SHLIB=on ../ && make && sudo make install

.PHONY: all clean

clean:
	rm -f ./*.o
	rm -f ./*.out
