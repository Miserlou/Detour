// most of this copied from http://www.tcpdump.org/pcap.html and other places

#include <pcap.h>
#include "common.c"
#include "uthash.h"


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl;		/* version << 4 | header length >> 2 */
  u_char ip_tos;		/* type of service */
  u_short ip_len;		/* total length */
  u_short ip_id;		/* identification */
  u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  u_char ip_ttl;		/* time to live */
  u_char ip_p;  		/* protocol */
  u_short ip_sum;		/* checksum */
  struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport;     	/* source port */
  u_short th_dport;     	/* destination port */
  tcp_seq th_seq;		/* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */
  u_char th_offx2;      	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;		/* window */
  u_short th_sum;		/* checksum */
  u_short th_urp;		/* urgent pointer */
};



struct con {
  UT_hash_handle hh;
  char name[47];
  unsigned int bytesA, bytesB;
  unsigned int idle;
};
struct con *cons = NULL;

time_t t;
bool even;


void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
  unsigned int len = h->len;

  /* The ethernet header */
  //const struct sniff_ethernet *ethernet = (struct sniff_ethernet*)(packet);
  /* The IP header */
  const struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  u_int size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  /* The TCP header */
  const struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  u_int size_tcp = TH_OFF(tcp)*4;
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }

  // construct name string
  // length of IP: 3+1+3+1+3+1+3=15
  // length of port: 5
  // total: 2*(15+1+5)+4+1=47 including '\0'
  char name[47];
  uint32_t ipA = ntohl(ip->ip_src.s_addr);
  uint32_t ipB = ntohl(ip->ip_dst.s_addr);
  sprintf(name, "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
      ipA>>24, (ipA>>16)&0xff, (ipA>>8)&0xff, ipA&0xff, ntohs(tcp->th_sport),
      ipB>>24, (ipB>>16)&0xff, (ipB>>8)&0xff, ipB&0xff, ntohs(tcp->th_dport));

  //printf("%s: %u\n", name, len);

  struct con *c;
  HASH_FIND_STR(cons, name, c);
  if (!c) {
    c = calloc(1, sizeof(struct con));
    if (!c) printf("calloc fail"), exit(1);
    strcpy(c->name, name);
    HASH_ADD_STR(cons, name, c);
  }

  if (even)
    c->bytesB += len;
  else
    c->bytesA += len;
  c->idle = 0;
}

int main(int argc, char **argv) {
  if (argc != 2) puts("invocation: ./pulserecord <interface>"), exit(1);
  char *dev = argv[1];

  setbuf(stdout, NULL);
  char errbuf[PCAP_ERRBUF_SIZE];
  printf("Device: %s\n", dev);

  mkdir("out", 0700);
  if (chdir("out")) perror("unable to enter directory 'out'"), exit(1);

  // We use a zero-timeout. The pcap manual says:
  // "to_ms is the read time out in milliseconds (a value of 0 means
  //  no time out; on at least some platforms, this means that you may
  //  wait until a sufficient number of packets arrive before seeing
  //  any packets, so you should use a non-zero timeout)."
  // That's simply not acceptable for us, so we can use a zero timeout
  // just as well and tell everyone to use a sensible OS. :D
  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
  if (!handle) printf("can't open device %s: %s\n", dev, errbuf), exit(1);
  if (pcap_datalink(handle) != DLT_EN10MB)
    printf("Device %s doesn't provide Ethernet headers - not supported\n", dev), exit(1);
  if (pcap_setnonblock(handle, 1, errbuf) == -1) printf("unable to go nonblocking\n"), exit(1);
  int pcap_fd = pcap_get_selectable_fd(handle);
  if (pcap_fd == -1) printf("unable to get a pcap fd\n"), exit(1);

  struct bpf_program fp; /* The compiled filter */
  if (pcap_compile(handle, &fp, "tcp", 1, PCAP_NETMASK_UNKNOWN) == -1) {
    printf("Couldn't parse filter: %s\n", pcap_geterr(handle));
    exit(1);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    printf("Couldn't install filter: %s\n", pcap_geterr(handle));
    exit(1);
  }

  t = round_up(real_seconds(), 2);
  even = (t&3) == 0; /* are we processing part 2/2 of one encoded bit? */
  while (1) {
    struct timespec dst, delta;
    dst.tv_sec = t;
    dst.tv_nsec = 0;

    // this inner loop runs until we hit a 2s-boundary
    while (1) {
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(pcap_fd, &rfds);
      struct timespec cur;
      int r = clock_gettime(CLOCK_REALTIME, &cur);
      assert(r==0);
      if (timespec_subtract(&delta, &dst, &cur)) break;
      r = pselect(pcap_fd+1, &rfds, NULL, NULL, &delta, NULL);
      if (r == -1) perror("select failed"), exit(1);
      if (r == 0) {
        // timeout
        break;
      } else {
        r = pcap_dispatch(handle, -1, packet_handler, NULL);
        if (r < 0) printf("pcap_dispatch failed\n"), exit(1);
      }
    }

    if (even) { // cycle complete
      struct con *c, *tmp;
      HASH_ITER(hh, cons, c, tmp) {
        if (c->idle >= 10) {
          HASH_DEL(cons, c);
          free(c);
          c = NULL; // just to be sure
          continue;
        }
        char bit = '_';
        if (!c->idle)
          bit = (c->bytesA < c->bytesB) ? '1' : '0';
        int fd = open(c->name, O_WRONLY|O_APPEND|O_CREAT, 0666);
        if (fd == -1) {
          perror("unable to open confile");
        } else {
w:;       ssize_t r = write(fd, &bit, 1);
          if (r == -1 && errno == EINTR) goto w;
          if (r == -1) perror("confile write failed");
          if (r == 0) puts("confile write failed");
          close(fd);
        }
        c->bytesA = 0;
        c->bytesB = 0;
        c->idle++;
      }
    }

    t += 2;
    even = !even;
  }

  return 0;
}
