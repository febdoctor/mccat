/* Multicast cat
   Copyright (c) 2004-2013 Wouter Cloetens <wouter@e2big.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <poll.h>

#define BUFSIZE 4096

static struct sockaddr_in addr, my_addr;
static unsigned int if_index;
static char *if_name;
static int use_multicast;
static int terminate;
static int show_status;
static int epoch;

static int ts_hexdump;
static int rtp_check;
static int quiet;

static void show_usage(const char *name);
static int parse_args(int argc, char *argv[]);
static void mainloop(int s);
static void hexdump(const unsigned char *buffer, size_t len);
static int ts_fprintf(FILE *f, struct timeval *tv, const char *format, ...);
static void sighandler(int signum);

int main(int argc, char *argv[])
{
    int s;
    sighandler_t oldint;
    struct sockaddr_in sin;
    struct ip_mreqn mreq;

    if (parse_args(argc, argv))
    {
	show_usage(argv[0]);
	return EXIT_FAILURE;
    }

    s = socket(addr.sin_family == AF_INET ? PF_INET : PF_INET6, SOCK_DGRAM, 0);
    if (s < 0)
    {
	fprintf(stderr, "Error opening socket: %s\n", strerror(errno));
	return EXIT_FAILURE;
    }
    sin = addr;
    sin.sin_addr.s_addr = addr.sin_addr.s_addr;

    if (use_multicast)
    {
        int optval = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
	{
	    fprintf(stderr, "Warning: could not set SO_REUSEADDR for multicast group %s: %m\n",
		    inet_ntoa(mreq.imr_multiaddr));
	}
    }

    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        close(s);
	fprintf(stderr, "Error binding to port %hu of %s: %s\n",
		ntohs(sin.sin_port), inet_ntoa(sin.sin_addr),
		strerror(errno));
	return EXIT_FAILURE;
    }

    if (use_multicast)
    {
	mreq.imr_multiaddr = addr.sin_addr;
	mreq.imr_address = my_addr.sin_addr;
	mreq.imr_ifindex = if_index;

	if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
	{
            close(s);
	    fprintf(stderr, "Error joining multicast group: %s\n", strerror(errno));
	    return EXIT_FAILURE;
	}
    }

    oldint = signal(SIGINT, sighandler);
    signal(SIGUSR1, sighandler);
    mainloop(s);
    signal(SIGINT, oldint);

    if (use_multicast)
    {
	mreq.imr_multiaddr = addr.sin_addr;
	mreq.imr_address = my_addr.sin_addr;
	mreq.imr_ifindex = if_index;

	if (setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
	{
	    fprintf(stderr, "Error leaving multicast group: %s\n", strerror(errno));
	}
    }
    close(s);
    return EXIT_SUCCESS;
}

static void sighandler(int signum)
{
    switch (signum)
    {
    case SIGINT:
    case SIGTERM:
        terminate = 1;
        break;
    case SIGUSR1:
        show_status = 1;
        break;
    }
}

static int ts_fprintf(FILE *f, struct timeval *tv, const char *format, ...)
{
    va_list ap;
    struct tm *dt;
    int offset;
    struct timeval now;

    if (tv == NULL)
    {
	gettimeofday(&now, NULL);
        tv = &now;
    }
    if (epoch)
        offset = fprintf(f, "%010d.%06lu ", (int)tv->tv_sec, tv->tv_usec);
    else
    {
        dt = gmtime(&tv->tv_sec);
        offset = fprintf(f, "%4d/%02d/%02d %02d:%02d:%02d.%06lu ",
                         dt->tm_year + 1900, dt->tm_mon + 1, dt->tm_mday,
                         dt->tm_hour, dt->tm_min, dt->tm_sec, tv->tv_usec);
    }
    va_start(ap, format);
    offset += vfprintf(f, format, ap);
    va_end(ap);

    return offset;
}

static void mainloop(int s)
{
    unsigned char buf[BUFSIZE];
    ssize_t n;
    ssize_t rtp_seq = -1;
    uint32_t ssrc = 0;
    struct pollfd fds[2];

    while (!terminate)
    {
        fds[0].fd = s;
        fds[0].events = POLLIN | POLLERR;
        fds[1].fd = STDIN_FILENO;
        fds[1].events = POLLERR;
        if (poll(fds, 2, -1) < 0)
        {
            if (errno != EINTR)
            {
                fprintf(stderr, "poll(): %m\n");
                break;
            }
            if (terminate)
            {
                fprintf(stderr, "\n");
                break;
            }
        }
        if (!fds[0].revents & POLLIN)
            continue;
	n = recv(s, buf, sizeof(buf), 0);
	if (n < 0)
	{
	    fprintf(stderr, "Error in recv() from (%s:%hu): %m\n",
		    inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            break;
	}
        if (n == 0)
	    break;
	if (rtp_check)
        {
            ssize_t new_rtp_seq;
            uint32_t new_ssrc;

	    if (n < 12)
                ts_fprintf(stderr, NULL, "read %d bytes: too short for RTP header\n", n);
            else
            {
                new_rtp_seq = (buf[2] << 8) + buf[3];
                new_ssrc = (((((buf[8] << 8) | buf[9]) << 8) | buf[10]) << 8) | buf[11];
                if (rtp_seq < 0)
                    ts_fprintf(stderr, NULL, "#%05d SSRC=0x%08x start\n", new_rtp_seq, new_ssrc);
                else if (new_ssrc != ssrc)
                        ts_fprintf(stderr, NULL, "#%05d SSRC=0x%08x SSRC change,   last seen #%05d SSRC=0x%08x\n",
                                   new_rtp_seq, new_ssrc, rtp_seq, ssrc);
                else if (!(((new_rtp_seq == 0) && (rtp_seq == 65535)) ||
                        new_rtp_seq == rtp_seq + 1))
                        ts_fprintf(stderr, NULL, "#%05d SSRC=0x%08x discontinuity, last seen #%05d SSRC=0x%08x\n",
                                   new_rtp_seq, new_ssrc, rtp_seq, ssrc);
                rtp_seq = new_rtp_seq;
                ssrc = new_ssrc;
                if (show_status)
                {
                    ts_fprintf(stderr, NULL, "#%05d SSRC=0x%08x\n", rtp_seq, ssrc);
                    show_status = 0;
                }
            }
        }
        if (!quiet)
        {
            if (ts_hexdump)
	        hexdump(buf, n);
	    else
            {
                fwrite(buf, n, 1, stdout);
                fflush(stdout);
            }
        }
    }
}

static int parse_args(int argc, char *argv[])
{
    static const struct option options[] = {
        { "hex",     no_argument,       &ts_hexdump, 'x'},
        { "quiet",   no_argument,       &quiet,      'q'},
        { "rtp",     no_argument,       &rtp_check,  'r'},
        { "epoch",   no_argument,       &epoch,      'e'},
        { "if",      required_argument, NULL,        'i'},
        { "help",    no_argument,       NULL,        '?'},
        { 0, 0, 0, 0 }
    };
    int c;
    struct hostent *he;
    int s;
    struct ifreq ifr;
    char *address, *port;

    while ((c = getopt_long(argc, argv, "W;xqeri:?", options, NULL)) != -1)
    {
        switch (c)
        {
        case 'x':
            ts_hexdump = c;
            break;
        case 'q':
            quiet = c;
            break;
        case 'e':
            epoch = c;
            break;
        case 'r':
            rtp_check = c;
            break;
        case 0:
            break;
        case 'i':
            if_name = optarg;
            break;
        case '?':
        default:
            return 1;
        }
        //printf("optind = %d\n", optind);
    }

    if (optind + 2 > argc)
        return 1;
    address = argv[optind++];
    port = argv[optind++];

    he = gethostbyname(address);
    if (he == NULL)
    {
	fprintf(stderr, "Failed to resolve \"%s\": %s\n", argv[1], strerror(h_errno));
	return 1;
    }
    addr.sin_family = he->h_addrtype;
    addr.sin_port = htons(atoi(port));
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if ((addr.sin_family == AF_INET) && IN_MULTICAST(ntohl(addr.sin_addr.s_addr)))
    {
        use_multicast = 1;

	if (if_name)
	{
	    if_index = if_nametoindex(if_name);

	    if (if_index == 0)
	    {
		fprintf(stderr, "No such interface: %s\n", if_name);
		return 1;
	    }
	}
	else
	{
	    struct if_nameindex *nidx;

	    nidx = if_nameindex();
	    if (nidx[0].if_index == 0)
	    {
		fprintf(stderr, "Failed to find any network interfaces.\n");
		return 1;
	    }
	    if_index = nidx[0].if_index;
	    if_name = nidx[0].if_name;
	}

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
	    perror("socket");
	    return 1;
	}
	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, if_name);
	if (ioctl(s, SIOCGIFDSTADDR, &ifr) < 0)
	{
	    fprintf(stderr, "Failed to find IP address for interface %s: %m\n", if_name);
	    close(s);
	    return 1;
	}
	close(s);

	my_addr = *(struct sockaddr_in *)&ifr.ifr_addr;
	if (my_addr.sin_family == 0xFFFF || my_addr.sin_family == 0)
	{
	    fprintf(stderr, "Failed to find IP address for interface %s: unknown or invalid address family\n",
		    if_name);
	    return 1;
	}
    }
    else
    {
	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = INADDR_ANY;
    }

    return 0;
}

static void show_usage(const char *name)
{
    char *cmd = basename(name);

    fprintf(stderr, "Usage: %s [options] <ip address> <port>\n", cmd);
    fprintf(stderr, "  -i|--if              network interface name\n");
    fprintf(stderr, "  -r|--rtp             follow and check RTP sequence numbers\n");
    fprintf(stderr, "  -q|--quiet           do not dump stream data on stdout\n");
    fprintf(stderr, "  -x|--hexdump         dump stream data on stdout as a hex/ASCCI dump\n");
    fprintf(stderr, "  -e|--epoch           show timestamps as seconds since epoch\n");
    fprintf(stderr, "  -?|--help            print this message and exit\n");
    fprintf(stderr, "Signals:\n");
    fprintf(stderr, "  SIGUSR1              in RTP mode, print next packet's info\n");
}

static void hexdump(const unsigned char *buffer, size_t len)
{
    unsigned int i;
    int j, k;

    printf("data length: %d = 0x%x\n", (int)len, (int)len);

    for (i = 0, j = 0; i < len; i++, j++)
    {
        if (i % 16 == 0)
            printf("%04x  ", i);
        printf("%02x ", ((int)buffer[i] & 0xff));
        if (j >= 15)
        {
            for ( ; j >= 0; j--)
                printf("%c",
                       ((buffer[i - j] >= ' ') && (buffer[i - j] <= '~')) ?
                       buffer[i - j] : '.');
            printf ("\n");
        }
    }
    if (i % 16 != 0)
    {
        for (k = j; k <= 15; k++)
            printf("   ");
        for (k = j ; k > 0; k--)
            printf("%c",
                   ((buffer[i - k] >= ' ') && (buffer[i - k] <= '~')) ?
                   buffer[i - k] : '.');
        for (k = j ; k <= 15; k++)
            printf(" ");
    }
    printf("\n");
    fflush(stdout);
}
