CC?=	cc
CFLAGS=	-fstack-protector
TARGETS=	arpspoof
OBJ=	arpspoof.o

all:	$(TARGETS)

.c.o:
	$(CC) $(CFLAGS) -c $<

arpspoof:	$(OBJ)
		$(CC) $(CFLAGS) -o $@ $(OBJ)

clean:
	rm -fr *.o arpspoof
