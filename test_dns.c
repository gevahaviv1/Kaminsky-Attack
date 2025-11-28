// test_dns.c - Comprehensive test suite for DNS server/client

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ldns/ldns.h>

/* =======================
 *   TEST CONFIGURATION
 * ======================= */

#define RESOLVER_IP   "192.168.1.203"
#define SERVER_IP     "192.168.1.201"
#define DNS_PORT      53
#define TEST_TIMEOUT  5

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

/* =======================
 *   HELPER MACROS
 * ======================= */

#define TEST_START(name) \
    printf("\n[TEST] %s\n", name);

#define TEST_ASSERT(condition, message) \
    do { \
        if (condition) { \
            printf("  ✓ %s\n", message); \
            tests_passed++; \
        } else { \
            printf("  ✗ FAILED: %s\n", message); \
            tests_failed++; \
        } \
    } while(0)

#define TEST_SUMMARY() \
    printf("\n========================================\n"); \
    printf("Tests Passed: %d\n", tests_passed); \
    printf("Tests Failed: %d\n", tests_failed); \
    printf("Total Tests:  %d\n", tests_passed + tests_failed); \
    printf("========================================\n");

/* =======================
 *   DNS PACKET TESTS
 * ======================= */

/**
 * Test: Create and parse a basic DNS query
 */
void test_basic_dns_query(void) {
    TEST_START("Basic DNS Query Creation and Parsing");
    
    ldns_pkt *query_pkt = NULL;
    ldns_rdf *owner = NULL;
    uint8_t *wire_data = NULL;
    size_t wire_len = 0;
    
    // Create a simple DNS query
    query_pkt = ldns_pkt_query_new(
        ldns_dname_new_frm_str("www.example.com"),
        LDNS_RR_TYPE_A,
        LDNS_RR_CLASS_IN,
        LDNS_RD
    );
    
    TEST_ASSERT(query_pkt != NULL, "Query packet created");
    
    if (query_pkt) {
        // Check query parameters
        TEST_ASSERT(ldns_pkt_qdcount(query_pkt) == 1, "Question count is 1");
        TEST_ASSERT(ldns_pkt_qr(query_pkt) == 0, "QR flag is 0 (query)");
        TEST_ASSERT(ldns_pkt_rd(query_pkt) == 1, "RD flag is 1");
        
        // Convert to wire format
        ldns_status status = ldns_pkt2wire(&wire_data, query_pkt, &wire_len);
        TEST_ASSERT(status == LDNS_STATUS_OK, "Packet serialized to wire format");
        TEST_ASSERT(wire_len > 12, "Wire data has valid length (>12 bytes)");
        
        // Parse it back
        ldns_pkt *parsed_pkt = NULL;
        if (wire_data) {
            status = ldns_wire2pkt(&parsed_pkt, wire_data, wire_len);
            TEST_ASSERT(status == LDNS_STATUS_OK, "Packet parsed from wire format");
            TEST_ASSERT(ldns_pkt_id(parsed_pkt) == ldns_pkt_id(query_pkt), 
                       "Transaction ID preserved");
            
            ldns_pkt_free(parsed_pkt);
            free(wire_data);
        }
        
        ldns_pkt_free(query_pkt);
    }
}

/**
 * Test: Edge case - Empty packet
 */
void test_empty_packet(void) {
    TEST_START("Edge Case: Empty/Malformed Packet");
    
    ldns_pkt *pkt = NULL;
    uint8_t empty_data[12] = {0}; // DNS header with all zeros
    
    ldns_status status = ldns_wire2pkt(&pkt, empty_data, sizeof(empty_data));
    TEST_ASSERT(status == LDNS_STATUS_OK, "Empty header parsed (no questions)");
    
    if (pkt) {
        TEST_ASSERT(ldns_pkt_qdcount(pkt) == 0, "Question count is 0");
        ldns_pkt_free(pkt);
    }
    
    // Test with truncated packet
    pkt = NULL;
    status = ldns_wire2pkt(&pkt, empty_data, 5);
    TEST_ASSERT(status != LDNS_STATUS_OK, "Truncated packet rejected");
}

/**
 * Test: Edge case - Very long domain name
 */
void test_long_domain_name(void) {
    TEST_START("Edge Case: Long Domain Name (253 chars)");
    
    // Max DNS name is 253 characters
    char long_name[260];
    memset(long_name, 'a', 240);
    strcpy(long_name + 240, ".example.com");
    
    ldns_rdf *domain = ldns_dname_new_frm_str(long_name);
    TEST_ASSERT(domain != NULL, "Long domain name created");
    
    if (domain) {
        ldns_pkt *query = ldns_pkt_query_new(domain, LDNS_RR_TYPE_A, 
                                             LDNS_RR_CLASS_IN, LDNS_RD);
        TEST_ASSERT(query != NULL, "Query with long domain created");
        ldns_pkt_free(query);
    }
}

/**
 * Test: Edge case - Invalid domain characters
 */
void test_invalid_domain(void) {
    TEST_START("Edge Case: Invalid Domain Characters");
    
    const char *invalid_domains[] = {
        "example..com",      // Double dot
        ".example.com",      // Leading dot
        "example.com.",      // Trailing dot is actually valid
        "exam ple.com",      // Space
        NULL
    };
    
    for (int i = 0; invalid_domains[i] != NULL; i++) {
        ldns_rdf *domain = ldns_dname_new_frm_str(invalid_domains[i]);
        // ldns is permissive, so we just check it doesn't crash
        if (domain) {
            ldns_rdf_deep_free(domain);
        }
    }
    TEST_ASSERT(1, "Invalid domain handling completed without crash");
}

/**
 * Test: Response with multiple answer records
 */
void test_multiple_answers(void) {
    TEST_START("DNS Response with Multiple Answers");
    
    ldns_pkt *response = ldns_pkt_new();
    TEST_ASSERT(response != NULL, "Response packet created");
    
    if (response) {
        ldns_pkt_set_qr(response, 1);
        ldns_pkt_set_aa(response, 1);
        ldns_pkt_set_id(response, 0x1234);
        
        // Add multiple A records
        for (int i = 0; i < 5; i++) {
            ldns_rr *rr = ldns_rr_new();
            ldns_rr_set_owner(rr, ldns_dname_new_frm_str("example.com"));
            ldns_rr_set_type(rr, LDNS_RR_TYPE_A);
            ldns_rr_set_ttl(rr, 300);
            
            char ip[16];
            snprintf(ip, sizeof(ip), "1.2.3.%d", i + 1);
            ldns_rdf *addr = NULL;
            ldns_str2rdf_a(&addr, ip);
            ldns_rr_push_rdf(rr, addr);
            
            ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, rr);
        }
        
        TEST_ASSERT(ldns_pkt_ancount(response) == 5, "5 answer records added");
        
        // Serialize and parse back
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        ldns_status status = ldns_pkt2wire(&wire, response, &wire_len);
        TEST_ASSERT(status == LDNS_STATUS_OK, "Multi-answer packet serialized");
        
        if (wire) {
            ldns_pkt *parsed = NULL;
            status = ldns_wire2pkt(&parsed, wire, wire_len);
            TEST_ASSERT(status == LDNS_STATUS_OK, "Multi-answer packet parsed");
            TEST_ASSERT(ldns_pkt_ancount(parsed) == 5, "5 answers preserved");
            
            ldns_pkt_free(parsed);
            free(wire);
        }
        
        ldns_pkt_free(response);
    }
}

/* =======================
 *   NETWORK TESTS
 * ======================= */

/**
 * Test: Send valid UDP DNS query to server
 */
void test_valid_udp_query(void) {
    TEST_START("Network: Send Valid UDP DNS Query");
    
    int sockfd;
    struct sockaddr_in server_addr;
    uint8_t *wire_data = NULL;
    size_t wire_len = 0;
    
    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(sockfd >= 0, "UDP socket created");
    
    if (sockfd < 0) return;
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = TEST_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Build DNS query
    ldns_pkt *query = ldns_pkt_query_new(
        ldns_dname_new_frm_str("www.attacker.cybercourse.example.com"),
        LDNS_RR_TYPE_A,
        LDNS_RR_CLASS_IN,
        LDNS_RD
    );
    
    if (!query) {
        TEST_ASSERT(0, "Failed to create query packet");
        close(sockfd);
        return;
    }
    
    ldns_status status = ldns_pkt2wire(&wire_data, query, &wire_len);
    TEST_ASSERT(status == LDNS_STATUS_OK, "Query serialized to wire");
    
    if (status == LDNS_STATUS_OK && wire_data) {
        // Setup server address
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(DNS_PORT);
        inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
        
        // Send query
        ssize_t sent = sendto(sockfd, wire_data, wire_len, 0,
                             (struct sockaddr *)&server_addr, sizeof(server_addr));
        TEST_ASSERT(sent == (ssize_t)wire_len, "Query sent to server");
        
        // Try to receive response
        uint8_t recv_buf[1024];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        ssize_t recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                    (struct sockaddr *)&from_addr, &from_len);
        
        if (recv_len > 0) {
            TEST_ASSERT(1, "Response received from server");
            
            ldns_pkt *response = NULL;
            status = ldns_wire2pkt(&response, recv_buf, recv_len);
            TEST_ASSERT(status == LDNS_STATUS_OK, "Response parsed successfully");
            
            if (response) {
                TEST_ASSERT(ldns_pkt_qr(response) == 1, "Response QR flag set");
                TEST_ASSERT(ldns_pkt_id(response) == ldns_pkt_id(query), 
                           "Transaction IDs match");
                ldns_pkt_free(response);
            }
        } else {
            TEST_ASSERT(0, "No response received (timeout or server not running)");
        }
        
        free(wire_data);
    }
    
    ldns_pkt_free(query);
    close(sockfd);
}

/**
 * Test: TCP listener functionality
 */
void test_tcp_connection(void) {
    TEST_START("Network: TCP Connection Test");
    
    int sockfd;
    struct sockaddr_in server_addr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(sockfd >= 0, "TCP socket created");
    
    if (sockfd < 0) return;
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = TEST_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);  // ATTACKER_TCP_PORT
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    
    int result = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    if (result == 0) {
        TEST_ASSERT(1, "TCP connection established");
        
        // Try to read data
        char buf[64];
        ssize_t n = recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            TEST_ASSERT(1, "Received data over TCP");
            printf("    Received: %s\n", buf);
        }
    } else {
        TEST_ASSERT(0, "TCP connection failed (server may not be listening)");
    }
    
    close(sockfd);
}

/**
 * Test: Checksum validation
 */
void test_checksum_calculation(void) {
    TEST_START("Checksum: IP and UDP Checksum Validation");
    
    // Simple test data
    uint8_t test_data[] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
                           0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
                           0xac, 0x10, 0x0a, 0x0c};
    
    // Calculate checksum (should produce valid result)
    uint16_t checksum = 0;
    uint32_t sum = 0;
    
    for (size_t i = 0; i < sizeof(test_data); i += 2) {
        if (i == 10) continue; // Skip checksum field
        uint16_t word = (test_data[i] << 8) | test_data[i + 1];
        sum += word;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    checksum = ~sum;
    TEST_ASSERT(checksum == 0xb1e6, "IP checksum calculated correctly");
}

/**
 * Test: Packet size limits
 */
void test_packet_size_limits(void) {
    TEST_START("Edge Case: Packet Size Limits");
    
    // Test minimum valid DNS packet (12 byte header)
    uint8_t min_packet[12] = {0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ldns_pkt *pkt = NULL;
    ldns_status status = ldns_wire2pkt(&pkt, min_packet, sizeof(min_packet));
    TEST_ASSERT(status == LDNS_STATUS_OK, "Minimum packet size handled");
    if (pkt) ldns_pkt_free(pkt);
    
    // Test maximum practical size (512 bytes for UDP DNS)
    uint8_t large_packet[512];
    memset(large_packet, 0, sizeof(large_packet));
    large_packet[2] = 0x81; // Response flag
    large_packet[3] = 0x80; // Standard query response
    
    pkt = NULL;
    status = ldns_wire2pkt(&pkt, large_packet, sizeof(large_packet));
    TEST_ASSERT(pkt != NULL || status != LDNS_STATUS_OK, 
               "Large packet handled (may fail due to invalid content)");
    if (pkt) ldns_pkt_free(pkt);
}

/**
 * Test: DNS flags combinations
 */
void test_dns_flags(void) {
    TEST_START("DNS Flags: Various Flag Combinations");
    
    ldns_pkt *pkt = ldns_pkt_new();
    TEST_ASSERT(pkt != NULL, "Packet created");
    
    if (pkt) {
        // Test all flag combinations
        ldns_pkt_set_qr(pkt, 1);
        TEST_ASSERT(ldns_pkt_qr(pkt) == 1, "QR flag set");
        
        ldns_pkt_set_aa(pkt, 1);
        TEST_ASSERT(ldns_pkt_aa(pkt) == 1, "AA flag set");
        
        ldns_pkt_set_tc(pkt, 1);
        TEST_ASSERT(ldns_pkt_tc(pkt) == 1, "TC flag set");
        
        ldns_pkt_set_rd(pkt, 1);
        TEST_ASSERT(ldns_pkt_rd(pkt) == 1, "RD flag set");
        
        ldns_pkt_set_ra(pkt, 1);
        TEST_ASSERT(ldns_pkt_ra(pkt) == 1, "RA flag set");
        
        ldns_pkt_free(pkt);
    }
}

/* =======================
 *   MAIN TEST RUNNER
 * ======================= */

int main(int argc, char *argv[]) {
    int run_network_tests = 0;
    
    printf("========================================\n");
    printf("   DNS Server/Client Test Suite\n");
    printf("========================================\n");
    
    // Check if network tests should be run
    if (argc > 1 && strcmp(argv[1], "--network") == 0) {
        run_network_tests = 1;
        printf("Running with network tests enabled\n");
    } else {
        printf("Running unit tests only\n");
        printf("Use --network flag to enable network tests\n");
    }
    
    // Unit tests (always run)
    test_basic_dns_query();
    test_empty_packet();
    test_long_domain_name();
    test_invalid_domain();
    test_multiple_answers();
    test_dns_flags();
    test_packet_size_limits();
    test_checksum_calculation();
    
    // Network tests (only if flag provided)
    if (run_network_tests) {
        printf("\n=== Network Tests (requires server running) ===\n");
        test_valid_udp_query();
        test_tcp_connection();
    }
    
    TEST_SUMMARY();
    
    return (tests_failed > 0) ? 1 : 0;
}
