#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <ldns/ldns.h>

#define BUFFER_SIZE 1024

#define PORT_DNS 53

/**
 * parse_dns_query - Parse raw DNS query buffer into ldns packet structure
 * @buffer: Raw DNS query buffer
 * @len: Length of the buffer
 * @query_pkt: Pointer to store the parsed packet (output parameter)
 * 
 * Returns: LDNS_STATUS_OK on success, error status otherwise
 */
ldns_status parse_dns_query(char *buffer, int len, ldns_pkt **query_pkt) {
    ldns_status status = ldns_wire2pkt(query_pkt, (uint8_t *)buffer, len);
    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to parse DNS query: %s\n", 
                ldns_get_errorstr_by_id(status));
    }
    return status;
}

/**
 * log_client_info - Log client IP address and source port
 * @client_addr: Client's socket address structure
 * 
 * This function extracts and displays the source port which is critical
 * for the Kaminsky DNS cache poisoning attack.
 */
void log_client_info(struct sockaddr_in *client_addr) {
    uint16_t source_port = ntohs(client_addr->sin_port);
    char *client_ip = inet_ntoa(client_addr->sin_addr);
    
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║ DNS Query Received                                 ║\n");
    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║ Source IP:   %-37s ║\n", client_ip);
    printf("║ Source Port: %-37u ║\n", source_port);
    printf("╚════════════════════════════════════════════════════╝\n");
}

/**
 * print_query_details - Display DNS query name and type
 * @query_pkt: Parsed DNS query packet
 * 
 * Extracts and prints the queried domain name and record type.
 */
void print_query_details(ldns_pkt *query_pkt) {
    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
    if (question) {
        char *qname = ldns_rdf2str(ldns_rr_owner(question));
        ldns_rr_type qtype = ldns_rr_get_type(question);
        printf("Query: %s (Type: %s)\n\n", qname, ldns_rr_type2str(qtype));
        free(qname);
    }
}

/**
 * create_dns_response - Build a DNS response packet with dummy answer
 * @query_pkt: Original query packet
 * 
 * Creates a DNS response with:
 * - Same transaction ID as query
 * - Authoritative Answer (AA) flag set
 * - A record pointing to 1.2.3.4
 * 
 * Returns: Newly allocated response packet (caller must free)
 */
ldns_pkt *create_dns_response(ldns_pkt *query_pkt) {
    ldns_pkt *response_pkt = ldns_pkt_new();
    uint16_t query_id = ldns_pkt_id(query_pkt);
    
    // Set response flags
    ldns_pkt_set_id(response_pkt, query_id);
    ldns_pkt_set_qr(response_pkt, 1);  // This is a response
    ldns_pkt_set_aa(response_pkt, 1);  // Authoritative answer
    ldns_pkt_set_opcode(response_pkt, ldns_pkt_get_opcode(query_pkt));
    ldns_pkt_set_rd(response_pkt, ldns_pkt_rd(query_pkt));  // Copy RD from query
    ldns_pkt_set_ra(response_pkt, 0);  // Recursion not available (authoritative server)
    ldns_pkt_set_ad(response_pkt, 0);  // Zero flag (authentic data)
    ldns_pkt_set_cd(response_pkt, 0);  // Zero flag (checking disabled)
    
    // Copy question section
    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
    ldns_pkt_set_qdcount(response_pkt, 1);
    ldns_pkt_push_rr(response_pkt, LDNS_SECTION_QUESTION, ldns_rr_clone(question));
    
    // Create answer record (A record pointing to 1.2.3.4)
    ldns_rr *answer = ldns_rr_new();
    ldns_rr_set_owner(answer, ldns_rdf_clone(ldns_rr_owner(question)));
    ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
    ldns_rr_set_ttl(answer, 300);
    
    ldns_rdf *rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "1.2.3.4");
    ldns_rr_push_rdf(answer, rdf);
    ldns_pkt_push_rr(response_pkt, LDNS_SECTION_ANSWER, answer);
    
    return response_pkt;
}

/**
 * send_dns_response - Convert response packet to wire format and send
 * @sockfd: UDP socket file descriptor
 * @client_addr: Client's socket address to send response to
 * @response_pkt: DNS response packet to send
 * 
 * Converts the packet to wire format and sends it via UDP.
 * 
 * Returns: 0 on success, -1 on failure
 */
int send_dns_response(int sockfd, struct sockaddr_in *client_addr, 
                      ldns_pkt *response_pkt) {
    uint8_t *response_wire = NULL;
    size_t response_size = 0;
    
    ldns_status status = ldns_pkt2wire(&response_wire, response_pkt, &response_size);
    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to convert packet to wire format\n");
        return -1;
    }
    
    int sent = sendto(sockfd, response_wire, response_size, 0,
                      (struct sockaddr *)client_addr, sizeof(*client_addr));
    free(response_wire);
    
    return (sent < 0) ? -1 : 0;
}

/**
 * handle_dns_query - Main handler for incoming DNS queries
 * @sockfd: UDP socket file descriptor
 * @client_addr: Client's socket address
 * @buffer: Raw DNS query buffer
 * @len: Length of the buffer
 * 
 * Orchestrates the complete DNS query handling process:
 * 1. Parse the query
 * 2. Log client information (especially source port for Kaminsky attack)
 * 3. Display query details
 * 4. Create response
 * 5. Send response back to client
 */
void handle_dns_query(int sockfd, struct sockaddr_in *client_addr, 
                      char *buffer, int len) {
    ldns_pkt *query_pkt = NULL;
    ldns_pkt *response_pkt = NULL;
    
    // Parse incoming query
    if (parse_dns_query(buffer, len, &query_pkt) != LDNS_STATUS_OK) {
        return;
    }
    
    // Log client info (captures source port for attack)
    log_client_info(client_addr);
    
    // Display query details
    print_query_details(query_pkt);
    
    // Build response packet
    response_pkt = create_dns_response(query_pkt);
    
    // Send response
    send_dns_response(sockfd, client_addr, response_pkt);
    
    // Cleanup
    ldns_pkt_free(query_pkt);
    ldns_pkt_free(response_pkt);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt,
                   sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(sockfd);
        exit(1);
    }
    opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt,
                   sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEPORT) failed...\n");
        close(sockfd);
        exit(1);
    }

    // Bind socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT_DNS);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DNS Server listening on UDP port %d\n", PORT_DNS);
    printf("Waiting for queries from BIND 9.4.1 recursive resolver...\n\n");

    // Receive and handle DNS queries
    while (1) {
        int bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                      (struct sockaddr *)&client_addr, &addr_size);
        
        if (bytes_received < 0) {
            perror("recvfrom");
            continue;
        }

        // Handle the DNS query and capture source port
        handle_dns_query(sockfd, &client_addr, buffer, bytes_received);
    }

    close(sockfd);
    return 0;
}