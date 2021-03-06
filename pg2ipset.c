/*
    pg2ipset.c - Convert PeerGuardian lists to IPSet scripts.
    Copyright (C) 2009-2010, me@maeyanie.com

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char* argv[]) {
	FILE* ifp;
	FILE* ofp;
	const char* rulename;
	char* line = NULL;
	size_t linelen = 0;
	char* fromaddr;
	char* toaddr;
	unsigned int linecount = 0;
	char* tok;

	if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		fprintf(stderr, "Usage: %s [<input> [<output> [<set name>]]]\n", argv[0]);
		fprintf(stderr, "Input should be a PeerGuardian .p2p file, blank or '-' reads from stdin.\n");
		fprintf(stderr, "Output is suitable for usage by 'ipset restore', blank or '-' prints to stdout.\n");
		fprintf(stderr, "Set name is 'IPFILTER' if not specified.\n");
		fprintf(stderr, "Example: curl http://www.example.com/guarding.p2p | %s | ipset restore\n", argv[0]);
		return 0;
	}

	if (argc < 2 || !strcmp(argv[1], "-")) {
		ifp = stdin;
	} else {
		ifp = fopen(argv[1], "r");
	}
	if (!ifp) { perror("Could not open input file"); return -errno; }

	if (argc < 3 || !strcmp(argv[2], "-")) {
		ofp = stdout;
	} else {
		ofp = fopen(argv[2], "w");
	}
	if (!ofp) { perror("Could not open output file"); return -errno; }

	if (argc < 4) {
		rulename = "IPFILTER";
	} else {
		rulename = argv[3];
	}

	while (getline(&line, &linelen, ifp) > 0) {
		linecount++;
		tok = line;

		fromaddr = strrchr(tok, ':');
		if (!fromaddr) {
			fprintf(stderr, "Line %u: Failed parsing 'from' address.\n", linecount);
			continue;
		}
		*fromaddr++ = 0;

		toaddr = strchr(fromaddr, '-');
		if (!toaddr) {
			fprintf(stderr, "Line %u: Failed parsing 'to' address.\n", linecount);
			continue;
		}
		*toaddr++ = 0;
		fprintf(ofp, "add -exist %s %s-%s\n", rulename, fromaddr, toaddr);
	}

	fprintf(ofp, "COMMIT\n");
//	fprintf(stderr, "Converted %u rules.\n", linecount);
	return 0;
}

// EOF
