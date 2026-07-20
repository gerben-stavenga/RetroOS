# COMMAND.COM build — tiny model .COM via Borland C++ 3.1.
#
# Two-step compile/link: bcc -c (-> .obj), tlink /t (.obj -> .com).
# /t  = tiny model output (.COM, single-segment, ORG 100h).
# c0t = tiny startup module; ct  = tiny model C runtime library.

CC      = bcc
LINK    = tlink
CFLAGS  = -mt -O -d -G- -w-
# /t = produce .COM (tiny model output). Tiny model shares the small-model
# C runtime (cs.lib) — only the startup module differs (c0t vs c0s).
LFLAGS  = /t

all: COMMAND.COM

command.obj: command.c
	$(CC) $(CFLAGS) -c command.c

COMMAND.COM: command.obj
	$(LINK) $(LFLAGS) c0t command.obj, command.com,, cs
	rename command.com COMMAND.COM

clean:
	del *.obj
	del *.com
