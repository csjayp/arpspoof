CC?=	cc
PREFIX?=/usr/local
CFLAGS=	-fstack-protector
TARGETS=	arpspoof
OBJ=	arpspoof.o

all:	$(TARGETS)

.c.o:
	$(CC) $(CFLAGS) -c $<

arpspoof:	$(OBJ)
		$(CC) $(CFLAGS) -o $@ $(OBJ)

install:
	[ -d $(PREFIX)/bin ] || mkdir -p $(PREFIX)/bin
	cp arpspoof $(PREFIX)/bin

deinstall:
	rm -f $(PREFIX)/bin/arpspoof

clean:
	rm -fr *.o arpspoof
