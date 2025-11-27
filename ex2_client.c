// ex2_client.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <pcap.h>
#include <ldns/ldns.h>

/* =======================
 *   CONSTANTS & GLOBALS
 * ======================= */

#define RESOLVER_IP        "192.168.1.203"   /* bind9res */
#define ROOT_NS_IP         "192.168.1.204"   /* effective root (אם צריך) */
#define ATTACKER_AUTH_IP   "192.168.1.201"   /* attacker-auth */
#define ATTACKER_CLIENT_IP "192.168.1.202"   /* this container */

#define DNS_PORT           53
#define MAX_SUBDOMAIN_LEN  256
#define MAX_ROUNDS         1000   /* אתה תבחר מספר הגיוני */
#define MAX_SPOOFED_PKTS   (65536 * 20) /* לפי הגבלה בתרגיל */

/* pcap handle for packet injection */
static pcap_t *g_pcap_handle = NULL;

/* learned resolver source port */
static uint16_t g_resolver_src_port = 0;

/* =======================
 *   UTILITY FUNCTIONS
 * ======================= */

/* Initialize pcap for packet injection on eth0 (inside container). */
static int init_pcap(void)
{
    /* TODO: open pcap on "eth0" with pcap_open_live, check errors, etc. */
    /* set g_pcap_handle on success */
    return 0;
}

/* Close pcap handle if open. */
static void cleanup_pcap(void)
{
    if (g_pcap_handle != NULL) {
        pcap_close(g_pcap_handle);
        g_pcap_handle = NULL;
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

/* Inject one spoofed packet into the network via pcap. */
static int inject_spoofed_packet(const uint8_t *buf, size_t len)
{
    /* TODO:
     * 1. Build full Ethernet + IP + UDP headers around DNS wire data.
     * 2. Use pcap_inject() / pcap_sendpacket() with g_pcap_handle.
     * 3. Make sure source IP is ROOT_NS_IP and dest IP is RESOLVER_IP.
     * 4. UDP src port = 53, dest port = g_resolver_src_port.
     * 5. Compute UDP checksum correctly (חובה בתרגיל).
     */
    (void)buf;
    (void)len;
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

    /* Seed RNG in case you use random subdomains or txid sequences. */
    (void)srand((unsigned int)time(NULL));

    if (init_pcap() != 0) {
        goto cleanup;
    }

    if (learn_resolver_source_port() != 0) {
        goto cleanup;
    }

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
    cleanup_pcap();
    return ret;
}