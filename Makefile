PREFIX?=/usr/local
DESTDIR?=

all: build

build:
	gcc -O3 -o pg2ipset pg2ipset.c

clean:
	rm pg2ipset

install:
	install pg2ipset ${DESTDIR}${PREFIX}/bin/pg2ipset
